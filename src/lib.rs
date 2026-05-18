//! PII tokenization policy entrypoint and filter wiring.
//!
//! Two-phase pipeline:
//!
//! 1. `on_request`: read the request body, scan it against every rule
//!    whose scope includes the request side, replace each match with a
//!    format-preserving mask, and enroll the (mask, original) pairs
//!    into a per-request `Vault`. Forward the masked body to the
//!    upstream. The Vault is handed off to the response phase via
//!    `RequestData<Vault>`.
//!
//! 2. `on_response`: read the response body and replace any of the
//!    Vault's masks with their originals (so the client sees real
//!    data again). When `unmaskResponseBody=false` the response body
//!    is forwarded unchanged.
//!
//! Body parsing strategy comes from `contentTypeMode`:
//!
//!   - `auto`: JSON-aware when the body's Content-Type indicates JSON,
//!     plaintext otherwise. JSON parse failures fall back to plaintext.
//!   - `json`: always try JSON-aware first; fall back to plaintext on
//!     parse error.
//!   - `text`: always plaintext on the raw bytes.

mod catalog;
mod config;
mod generated;
mod json_walk;
mod mask;
mod matcher;
mod unmask;

use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use pdk::cache::CacheBuilder;
use pdk::hl::*;
use pdk::logger;

use crate::config::{ContentTypeMode, PolicyConfig};
use crate::generated::config::Config;
use crate::mask::{seed_from, Vault};

/// Per-request payload carried from request phase to response phase.
struct RequestState {
    vault: Vault,
    is_json: bool,
}

#[entrypoint]
pub async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    _cache_builder: CacheBuilder,
) -> anyhow::Result<()> {
    let raw: Config = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("invalid policy configuration: {e}"))?;

    let cfg = PolicyConfig::from_raw((&raw).into())
        .map_err(|e| anyhow!("policy configuration rejected: {e}"))?;

    if cfg.rules.is_empty() {
        logger::info!(
            "pii-tokenization: policy loaded with 0 rules; all traffic will pass through unmodified"
        );
    } else {
        logger::info!(
            "pii-tokenization: policy loaded with {} rule(s); maskRequestBody={} unmaskResponseBody={} contentTypeMode={:?}",
            cfg.rules.len(),
            cfg.mask_request_body,
            cfg.unmask_response_body,
            cfg.content_type_mode
        );
    }

    let cfg = Rc::new(cfg);
    let request_cfg = cfg.clone();
    let response_cfg = cfg;

    let filter = on_request(move |request, _client: HttpClient| {
        let cfg = request_cfg.clone();
        async move { request_filter(request, cfg).await }
    })
    .on_response(
        move |response, _client: HttpClient, data: RequestData<RequestState>| {
            let cfg = response_cfg.clone();
            async move {
                response_filter(response, cfg, data).await;
            }
        },
    );

    launcher.launch(filter).await?;
    Ok(())
}

async fn request_filter(
    request: RequestHeadersState,
    cfg: Rc<PolicyConfig>,
) -> Flow<RequestState> {
    let req_is_json = is_json_content_type(request.handler().header("content-type").as_deref());

    if !cfg.mask_request_body || cfg.rules.is_empty() || !request.contains_body() {
        return Flow::Continue(RequestState {
            vault: Vault::empty(),
            is_json: req_is_json,
        });
    }

    let body_state = request.into_body_state().await;
    let body = body_state.handler().body();

    if body.len() > cfg.max_body_size_bytes {
        logger::warn!(
            "pii-tokenization: request body ({} bytes) exceeds maxBodySizeBytes ({}); passing through unmodified",
            body.len(),
            cfg.max_body_size_bytes
        );
        return Flow::Continue(RequestState {
            vault: Vault::empty(),
            is_json: req_is_json,
        });
    }

    let mut vault = Vault::new(seed_for_request(&body), cfg.max_vault_entries);

    let masked = mask_body(&body, &cfg, &mut vault, req_is_json);

    if let Err(e) = body_state.handler().set_body(&masked) {
        logger::error!("pii-tokenization: set_body failed: {e:?}; passing through");
        return Flow::Continue(RequestState {
            vault: Vault::empty(),
            is_json: req_is_json,
        });
    }

    if vault.truncations > 0 {
        logger::warn!(
            "pii-tokenization: vault hit maxVaultEntries cap; {} match(es) passed through unmasked",
            vault.truncations
        );
    }

    logger::debug!("pii-tokenization: enrolled {} mask(s) into vault", vault.len());

    Flow::Continue(RequestState {
        vault,
        is_json: req_is_json,
    })
}

async fn response_filter(
    response: ResponseHeadersState,
    cfg: Rc<PolicyConfig>,
    data: RequestData<RequestState>,
) {
    let state = match data {
        RequestData::Continue(s) => s,
        _ => return,
    };

    let resp_is_json = is_json_content_type(response.handler().header("content-type").as_deref());

    let needs_unmask = cfg.unmask_response_body && !state.vault.is_empty();
    let needs_response_side_mask = cfg
        .rules
        .iter()
        .any(|r| matches!(r.scope(), config::Scope::Response));

    if !needs_unmask && !needs_response_side_mask {
        return;
    }
    if !response.contains_body() {
        return;
    }

    let body_state = response.into_body_state().await;
    let body = body_state.handler().body();

    if body.len() > cfg.max_body_size_bytes {
        logger::warn!(
            "pii-tokenization: response body ({} bytes) exceeds maxBodySizeBytes ({}); passing through unmodified",
            body.len(),
            cfg.max_body_size_bytes
        );
        return;
    }

    // Determine JSON mode: prefer the response's actual Content-Type, but
    // honour a `text` override from the operator.
    let use_json = matches!(cfg.content_type_mode, ContentTypeMode::Json)
        || (matches!(cfg.content_type_mode, ContentTypeMode::Auto) && resp_is_json)
        || (state.is_json && resp_is_json);

    let mut vault = state.vault;
    let new_body = transform_response(&body, &cfg, &mut vault, use_json);

    if new_body.as_slice() == body.as_slice() {
        return;
    }

    if let Err(e) = body_state.handler().set_body(&new_body) {
        logger::error!("pii-tokenization: response set_body failed: {e:?}");
    }
}

fn mask_body(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault, body_is_json: bool) -> Vec<u8> {
    let use_json = matches!(cfg.content_type_mode, ContentTypeMode::Json)
        || (matches!(cfg.content_type_mode, ContentTypeMode::Auto) && body_is_json);

    if use_json {
        if let Ok(out) = json_walk::mask_json_request(body, cfg, vault) {
            return out;
        }
        // JSON parse failed; fall back to plaintext.
        logger::debug!("pii-tokenization: JSON parse failed; falling back to plaintext masking");
    }

    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            logger::debug!(
                "pii-tokenization: body is not UTF-8; passing through unmodified"
            );
            return body.to_vec();
        }
    };
    matcher::mask_request(text, cfg, vault).into_bytes()
}

fn transform_response(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault, use_json: bool) -> Vec<u8> {
    let needs_unmask = cfg.unmask_response_body && !vault.is_empty();
    let needs_response_side_mask = cfg
        .rules
        .iter()
        .any(|r| matches!(r.scope(), config::Scope::Response));

    // Response-side masking (scope=response) needs JSON awareness so it
    // doesn't mask object keys. Unmask, by contrast, must preserve the
    // body's byte length exactly: the gateway forwards the upstream's
    // Content-Length header, and any size drift (e.g. from re-serializing
    // a pretty-printed upstream response into compact JSON) leaves the
    // downstream client waiting for bytes that never arrive. Masks are
    // format-preserving so a raw textual unmask is length-stable, and
    // they're random ASCII that can't collide with JSON syntax.
    let masked: Vec<u8> = if needs_response_side_mask {
        if use_json {
            json_walk::mask_json_response(body, cfg, vault).unwrap_or_else(|_| {
                logger::debug!(
                    "pii-tokenization: response JSON parse failed; falling back to plaintext masking"
                );
                let text = std::str::from_utf8(body).unwrap_or("");
                matcher::mask_response(text, cfg, vault).into_bytes()
            })
        } else {
            let text = match std::str::from_utf8(body) {
                Ok(s) => s,
                Err(_) => {
                    logger::debug!("pii-tokenization: response body is not UTF-8; passing through");
                    return body.to_vec();
                }
            };
            matcher::mask_response(text, cfg, vault).into_bytes()
        }
    } else {
        body.to_vec()
    };

    if !needs_unmask {
        return masked;
    }

    let text = match std::str::from_utf8(&masked) {
        Ok(s) => s,
        Err(_) => {
            logger::debug!("pii-tokenization: response body is not UTF-8; skipping unmask");
            return masked;
        }
    };
    unmask::unmask_text(text, vault).into_bytes()
}

fn is_json_content_type(ct: Option<&str>) -> bool {
    let Some(ct) = ct else { return false };
    let lower = ct.to_ascii_lowercase();
    lower.starts_with("application/json")
        || lower.starts_with("application/problem+json")
        || lower.contains("+json")
}

/// Build a 32-byte ChaCha seed from request entropy. We hash `body`
/// (which the upstream cannot predict ahead of time) together with a
/// monotonic clock reading. The output is stable within a request but
/// varies across requests, so format-preserving masks for the same input
/// value differ across requests.
fn seed_for_request(body: &[u8]) -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let mut entropy = Vec::with_capacity(body.len().min(4096) + 8);
    entropy.extend_from_slice(&nanos.to_be_bytes());
    entropy.extend_from_slice(&body[..body.len().min(4096)]);
    seed_from(&entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_content_type_detection() {
        assert!(is_json_content_type(Some("application/json")));
        assert!(is_json_content_type(Some("application/json; charset=utf-8")));
        assert!(is_json_content_type(Some("APPLICATION/JSON")));
        assert!(is_json_content_type(Some("application/problem+json")));
        assert!(is_json_content_type(Some("application/vnd.api+json")));
        assert!(!is_json_content_type(Some("text/plain")));
        assert!(!is_json_content_type(Some("application/xml")));
        assert!(!is_json_content_type(None));
    }

    #[test]
    fn seed_for_request_varies() {
        let a = seed_for_request(b"alpha");
        let b = seed_for_request(b"bravo");
        assert_ne!(a, b);
    }
}
