//! JSON-aware mask. Walks the body once with a tiny tokenizer to find
//! the byte ranges of every string and number leaf value (skipping
//! object keys), then rewrites those ranges in-place by running the
//! masker on the original bytes. The output has the same length as the
//! input — critical because the gateway forwards the upstream's
//! `Content-Length` header without rewriting it, and any size drift
//! (e.g. from re-serializing a pretty-printed body via `serde_json`)
//! causes downstream resets / hangs.
//!
//! The masker is format-preserving (`a..z` -> `a..z`, `0..9` -> `0..9`,
//! everything else passes through unchanged), so the masked range has
//! exactly the same byte length as the original range.

use crate::config::PolicyConfig;
use crate::mask::Vault;
use crate::matcher::{mask_request, mask_response};

pub fn mask_json_request(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault) -> Result<Vec<u8>, ()> {
    transform_value_ranges(body, |slice| mask_request(slice, cfg, vault))
}

pub fn mask_json_response(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault) -> Result<Vec<u8>, ()> {
    transform_value_ranges(body, |slice| mask_response(slice, cfg, vault))
}

/// Find every JSON value-position byte range and rewrite it through
/// `transform`. Returns `Err(())` if the body is not valid JSON — the
/// caller falls back to plaintext masking on the raw bytes.
///
/// The algorithm: scan the bytes. Track whether the next string we
/// encounter is a key (just after `{` or `,` inside an object) or a
/// value. Capture the byte range of every string/number leaf at value
/// positions; ignore strings at key positions. Rewrite the captured
/// ranges by running `transform` on the original UTF-8 substring.
///
/// Returns the rewritten body. The output length equals the input
/// length, because the masker is format-preserving over ASCII alphanum
/// and passes everything else through unchanged.
fn transform_value_ranges<F>(body: &[u8], mut transform: F) -> Result<Vec<u8>, ()>
where
    F: FnMut(&str) -> String,
{
    // Validate JSON shape with serde_json — cheap and authoritative.
    // We don't use the parsed value; we just need to know it's parseable.
    let _: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;

    let ranges = collect_value_ranges(body)?;
    if ranges.is_empty() {
        return Ok(body.to_vec());
    }

    let mut out = Vec::with_capacity(body.len());
    let mut last = 0usize;
    for (start, end) in ranges {
        if start < last || end > body.len() || start > end {
            // Defensive: bail to plaintext if our scanner produced bad ranges.
            return Err(());
        }
        out.extend_from_slice(&body[last..start]);
        let original = match std::str::from_utf8(&body[start..end]) {
            Ok(s) => s,
            Err(_) => {
                out.extend_from_slice(&body[start..end]);
                last = end;
                continue;
            }
        };
        let replaced = transform(original);
        if replaced.len() == end - start {
            out.extend_from_slice(replaced.as_bytes());
        } else {
            // Length-preserving guarantee broken (shouldn't happen with our
            // masker, but guard against pathological data types). Pass the
            // original through to keep total body length stable.
            out.extend_from_slice(&body[start..end]);
        }
        last = end;
    }
    out.extend_from_slice(&body[last..]);
    Ok(out)
}

/// Single-pass scan over the JSON bytes. Returns sorted, non-overlapping
/// (start, end) byte ranges for every string/number value-position leaf.
/// Keys (strings immediately followed by `:`) are excluded.
fn collect_value_ranges(body: &[u8]) -> Result<Vec<(usize, usize)>, ()> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut stack: Vec<Ctx> = vec![Ctx::TopLevel];
    let mut i = 0usize;

    while i < body.len() {
        let b = body[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
            continue;
        }

        let ctx = *stack.last().ok_or(())?;
        match b {
            b'{' => {
                stack.push(Ctx::ObjectExpectingKeyOrEnd);
                i += 1;
            }
            b'}' => {
                if !matches!(ctx, Ctx::ObjectExpectingKeyOrEnd | Ctx::ObjectExpectingValue) {
                    return Err(());
                }
                stack.pop();
                advance_after_value(&mut stack);
                i += 1;
            }
            b'[' => {
                stack.push(Ctx::ArrayExpectingValueOrEnd);
                i += 1;
            }
            b']' => {
                if !matches!(ctx, Ctx::ArrayExpectingValueOrEnd) {
                    return Err(());
                }
                stack.pop();
                advance_after_value(&mut stack);
                i += 1;
            }
            b',' => {
                match ctx {
                    Ctx::ObjectExpectingKeyOrEnd | Ctx::ArrayExpectingValueOrEnd => {}
                    _ => return Err(()),
                }
                i += 1;
            }
            b':' => {
                // Transition from key to value position.
                if let Some(top) = stack.last_mut() {
                    if matches!(*top, Ctx::ObjectExpectingKeyOrEnd) {
                        *top = Ctx::ObjectExpectingValue;
                    } else {
                        return Err(());
                    }
                }
                i += 1;
            }
            b'"' => {
                let (content_start, end_after_quote) = scan_string(body, i)?;
                let content_end = end_after_quote - 1;
                let is_key = matches!(ctx, Ctx::ObjectExpectingKeyOrEnd);
                if !is_key {
                    ranges.push((content_start, content_end));
                    advance_after_value(&mut stack);
                }
                i = end_after_quote;
            }
            b't' | b'f' | b'n' => {
                // true / false / null: skip the literal, no range captured.
                let lit_end = scan_literal(body, i)?;
                advance_after_value(&mut stack);
                i = lit_end;
            }
            _ if b == b'-' || b.is_ascii_digit() => {
                let num_end = scan_number(body, i)?;
                ranges.push((i, num_end));
                advance_after_value(&mut stack);
                i = num_end;
            }
            _ => return Err(()),
        }
    }

    // Sanity: ranges should already be sorted by construction, but enforce.
    ranges.sort_by_key(|r| r.0);
    Ok(ranges)
}

/// After consuming a value, the surrounding container goes back to its
/// "expecting separator-or-end" state. (The TopLevel state stays.)
fn advance_after_value(stack: &mut [Ctx]) {
    if let Some(top) = stack.last_mut() {
        match *top {
            Ctx::ObjectExpectingValue => *top = Ctx::ObjectExpectingKeyOrEnd,
            // Array is already in "value-or-end" mode.
            Ctx::ArrayExpectingValueOrEnd => {}
            Ctx::TopLevel => {}
            Ctx::ObjectExpectingKeyOrEnd => {}
        }
    }
}

#[derive(Clone, Copy)]
enum Ctx {
    TopLevel,
    ObjectExpectingKeyOrEnd,
    ObjectExpectingValue,
    ArrayExpectingValueOrEnd,
}

/// `body[i] == '"'`. Returns `(content_start, end_after_closing_quote)`.
/// Handles backslash-escapes; does NOT decode them, so the returned
/// content range is the raw on-wire bytes between the quotes.
fn scan_string(body: &[u8], i: usize) -> Result<(usize, usize), ()> {
    debug_assert_eq!(body[i], b'"');
    let content_start = i + 1;
    let mut j = content_start;
    while j < body.len() {
        match body[j] {
            b'\\' => {
                // Skip escape; advance two bytes (or six for \uXXXX, but the
                // next iteration handles the trailing chars naturally).
                j = j.saturating_add(2);
            }
            b'"' => return Ok((content_start, j + 1)),
            _ => j += 1,
        }
    }
    Err(())
}

/// Skip a JSON literal (`true`, `false`, or `null`) starting at `i`.
fn scan_literal(body: &[u8], i: usize) -> Result<usize, ()> {
    let rest = &body[i..];
    if rest.starts_with(b"true") { Ok(i + 4) }
    else if rest.starts_with(b"false") { Ok(i + 5) }
    else if rest.starts_with(b"null") { Ok(i + 4) }
    else { Err(()) }
}

/// Skip a JSON number starting at `i`, return the index just past the
/// last digit/sign/exponent character.
fn scan_number(body: &[u8], i: usize) -> Result<usize, ()> {
    let mut j = i;
    if j < body.len() && body[j] == b'-' {
        j += 1;
    }
    while j < body.len() && body[j].is_ascii_digit() {
        j += 1;
    }
    if j < body.len() && body[j] == b'.' {
        j += 1;
        while j < body.len() && body[j].is_ascii_digit() {
            j += 1;
        }
    }
    if j < body.len() && (body[j] == b'e' || body[j] == b'E') {
        j += 1;
        if j < body.len() && (body[j] == b'+' || body[j] == b'-') {
            j += 1;
        }
        while j < body.len() && body[j].is_ascii_digit() {
            j += 1;
        }
    }
    if j == i { Err(()) } else { Ok(j) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RawConfig, RawRule};
    use crate::mask::seed_from;

    fn cfg_ssn() -> PolicyConfig {
        PolicyConfig::from_raw(RawConfig {
            mask_request_body: true,
            unmask_response_body: true,
            content_type_mode: Some("auto".into()),
            max_body_size_bytes: None,
            max_vault_entries: None,
            rules: vec![RawRule {
                name: "ssn".into(),
                rule_type: "builtin".into(),
                builtin_pattern: Some("GovernmentId/UsSsn".into()),
                custom_regex: None,
                data_type: Some("number".into()),
                values: vec![],
                values_text: None,
                scope: None,
            }],
        })
        .unwrap()
    }

    fn cfg_static_names() -> PolicyConfig {
        PolicyConfig::from_raw(RawConfig {
            mask_request_body: true,
            unmask_response_body: true,
            content_type_mode: Some("auto".into()),
            max_body_size_bytes: None,
            max_vault_entries: None,
            rules: vec![RawRule {
                name: "names".into(),
                rule_type: "static".into(),
                builtin_pattern: None,
                custom_regex: None,
                data_type: Some("name".into()),
                values: vec!["Amir Khan".into()],
                values_text: None,
                scope: None,
            }],
        })
        .unwrap()
    }

    #[test]
    fn mask_only_string_leaf() {
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw1"), 1000);
        let body = br#"{"customer":{"name":"Amir Khan"}}"#;
        let out = mask_json_request(body, &cfg, &mut v).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        // The key 'name' must remain intact.
        assert!(s.contains("\"name\":"), "got {s}");
        // The value must be masked.
        assert!(!s.contains("Amir Khan"));
    }

    #[test]
    fn keys_named_like_values_are_not_masked() {
        // Operator might have a key like "Amir Khan" — bizarre but legal.
        // Even so, only the value should be masked.
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw2"), 1000);
        let body = br#"{"Amir Khan":"Amir Khan"}"#;
        let out = mask_json_request(body, &cfg, &mut v).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("\"Amir Khan\":"));
        assert_eq!(s.matches("Amir Khan").count(), 1);
    }

    #[test]
    fn ssn_as_string_is_masked() {
        let cfg = cfg_ssn();
        let mut v = Vault::new(seed_from(b"jw3"), 1000);
        let body = br#"{"ssn":"123-45-6789"}"#;
        let out = mask_json_request(body, &cfg, &mut v).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("123-45-6789"));
        let re = regex::Regex::new(r#""ssn":"\d{3}-\d{2}-\d{4}""#).unwrap();
        assert!(re.is_match(s), "got {s}");
    }

    #[test]
    fn round_trip_through_unmask() {
        // The response phase unmasks via raw textual replace (length-
        // preserving — see lib::transform_response). Verify a JSON-aware
        // mask followed by a textual unmask round-trips correctly.
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw4"), 1000);
        let req_body = br#"{"customer":{"name":"Amir Khan"},"summary":"Customer Amir Khan is at risk."}"#;
        let masked = mask_json_request(req_body, &cfg, &mut v).unwrap();
        let masked_text = std::str::from_utf8(&masked).unwrap();
        let restored = crate::unmask::unmask_text(masked_text, &v);
        assert!(restored.contains("Amir Khan"));
    }

    #[test]
    fn invalid_json_returns_err() {
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw5"), 1000);
        let body = b"not-json";
        assert!(mask_json_request(body, &cfg, &mut v).is_err());
    }
}
