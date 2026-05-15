//! JSON-aware mask/unmask. Parses with `serde_json::Value`, walks
//! recursively, and rewrites only string and number leaf values. Object
//! keys, array indices, and structural punctuation are never touched, so
//! a customer's name appearing as the value of the `"name"` field is
//! masked but a key called `"name"` survives intact.
//!
//! Numbers are stringified for masking, then we try to reparse the
//! masked string back to a number. If reparsing fails (which can happen
//! at the edges of i64/u64/f64 representable space), we fall back to a
//! string and let the upstream handle the type drift.

use serde_json::Value;

use crate::config::PolicyConfig;
use crate::mask::Vault;
use crate::matcher::{mask_request, mask_response};
use crate::unmask::unmask_text;

pub fn mask_json_request(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault) -> Result<Vec<u8>, ()> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    walk_mut(&mut value, &mut |s| {
        let masked = mask_request(s, cfg, vault);
        if masked == *s { None } else { Some(masked) }
    });
    serde_json::to_vec(&value).map_err(|_| ())
}

pub fn mask_json_response(body: &[u8], cfg: &PolicyConfig, vault: &mut Vault) -> Result<Vec<u8>, ()> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    walk_mut(&mut value, &mut |s| {
        let masked = mask_response(s, cfg, vault);
        if masked == *s { None } else { Some(masked) }
    });
    serde_json::to_vec(&value).map_err(|_| ())
}

pub fn unmask_json(body: &[u8], vault: &Vault) -> Result<Vec<u8>, ()> {
    if vault.is_empty() {
        return Ok(body.to_vec());
    }
    let mut value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    walk_mut(&mut value, &mut |s| {
        let restored = unmask_text(s, vault);
        if restored == *s { None } else { Some(restored) }
    });
    serde_json::to_vec(&value).map_err(|_| ())
}

/// Walk a `serde_json::Value` and apply `f` to every string and number
/// leaf. `f` returns `Some(replacement)` to substitute, `None` to leave
/// the leaf alone. Numbers are stringified for `f`'s benefit and the
/// replacement is reparsed back to a number when possible (else stored
/// as a string, which is the right behaviour when masking a digit-only
/// SSN-as-number into another digit-only run that may exceed i64).
fn walk_mut<F>(value: &mut Value, f: &mut F)
where
    F: FnMut(&str) -> Option<String>,
{
    match value {
        Value::String(s) => {
            if let Some(replacement) = f(s) {
                *s = replacement;
            }
        }
        Value::Number(n) => {
            let s = n.to_string();
            if let Some(replacement) = f(&s) {
                if replacement == s {
                    return;
                }
                *value = parse_number_or_string(&replacement);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_mut(item, f);
            }
        }
        Value::Object(map) => {
            for (_key, v) in map {
                walk_mut(v, f);
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
}

fn parse_number_or_string(s: &str) -> Value {
    if let Ok(n) = s.parse::<i64>() {
        return Value::from(n);
    }
    if let Ok(n) = s.parse::<u64>() {
        return Value::from(n);
    }
    if let Ok(n) = s.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(n) {
            return Value::Number(num);
        }
    }
    Value::String(s.to_string())
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
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw4"), 1000);
        let req_body = br#"{"customer":{"name":"Amir Khan"},"summary":"Customer Amir Khan is at risk."}"#;
        let masked = mask_json_request(req_body, &cfg, &mut v).unwrap();
        // Simulate the upstream echoing the masked body back.
        let restored = unmask_json(&masked, &v).unwrap();
        let s = std::str::from_utf8(&restored).unwrap();
        assert!(s.contains("Amir Khan"));
    }

    #[test]
    fn invalid_json_returns_err() {
        let cfg = cfg_static_names();
        let mut v = Vault::new(seed_from(b"jw5"), 1000);
        let body = b"not-json";
        assert!(mask_json_request(body, &cfg, &mut v).is_err());
    }
}
