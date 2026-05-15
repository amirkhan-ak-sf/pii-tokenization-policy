//! Span finding and span-based rewriting.
//!
//! For a given input string we collect spans from every active rule
//! (regex and static literal), resolve overlaps with longest-match-wins,
//! then rebuild the output in a single pass: copy [last_end .. span.start]
//! from the original, append the mask, advance last_end to span.end.
//! Crucially, this never re-scans the masked output, so a format-
//! preserving mask cannot be re-matched by a later regex.
//!
//! Rule ordering: rules that come earlier in the operator's config win
//! ties on equal-length spans (operator intent first, longest match
//! second). The final tiebreaker is start offset.

use crate::config::{CompiledRule, DataType, PolicyConfig, Scope};
use crate::mask::Vault;

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    rule_idx: usize,
    data_type: DataType,
}

/// Mask the request body. Walks every rule whose scope applies to the
/// request, collects spans, resolves overlaps, and rewrites the output
/// using the vault. Values for rules whose scope is `Both` enroll into
/// the vault so the response phase can reverse them; values for rules
/// whose scope is `Request` are masked but NOT enrolled.
pub fn mask_request(input: &str, cfg: &PolicyConfig, vault: &mut Vault) -> String {
    rewrite(input, cfg, vault, ScopeFilter::Request)
}

/// Mask the response body for `scope=response` rules. Does NOT enroll
/// into the vault (the unmask path is for the response-side reversal of
/// what the request masked, not for newly minted masks).
pub fn mask_response(input: &str, cfg: &PolicyConfig, vault: &mut Vault) -> String {
    rewrite(input, cfg, vault, ScopeFilter::Response)
}

#[derive(Debug, Clone, Copy)]
enum ScopeFilter {
    Request,
    Response,
}

impl ScopeFilter {
    fn includes(self, scope: Scope) -> bool {
        match self {
            ScopeFilter::Request => scope.applies_to_request(),
            ScopeFilter::Response => scope.applies_to_response() && scope != Scope::Both,
            // ^ Both is handled by the unmask path on the response side,
            //   not by re-running the masker.
        }
    }
}

fn rewrite(input: &str, cfg: &PolicyConfig, vault: &mut Vault, filter: ScopeFilter) -> String {
    if input.is_empty() || cfg.rules.is_empty() {
        return input.to_string();
    }

    let mut spans: Vec<Span> = Vec::new();
    for (idx, rule) in cfg.rules.iter().enumerate() {
        if !filter.includes(rule.scope()) {
            continue;
        }
        match rule {
            CompiledRule::Regex { regex, data_type, .. } => {
                for m in regex.find_iter(input) {
                    spans.push(Span {
                        start: m.start(),
                        end: m.end(),
                        rule_idx: idx,
                        data_type: *data_type,
                    });
                }
            }
            CompiledRule::Static { ac, data_type, .. } => {
                for m in ac.find_iter(input) {
                    spans.push(Span {
                        start: m.start(),
                        end: m.end(),
                        rule_idx: idx,
                        data_type: *data_type,
                    });
                }
            }
        }
    }

    if spans.is_empty() {
        return input.to_string();
    }

    let resolved = resolve_overlaps(spans);

    let mut out = String::with_capacity(input.len());
    let mut last_end = 0usize;
    for span in resolved {
        if span.start < last_end {
            // Already covered by a previous (winning) span.
            continue;
        }
        out.push_str(&input[last_end..span.start]);
        let original = &input[span.start..span.end];
        let scope = cfg.rules[span.rule_idx].scope();
        let enroll = match filter {
            ScopeFilter::Request => scope.enrolls_into_vault(),
            ScopeFilter::Response => false,
        };
        let mask = vault.mask_value(original, span.data_type, enroll);
        out.push_str(&mask);
        last_end = span.end;
    }
    out.push_str(&input[last_end..]);
    out
}

/// Sort spans and drop any that are dominated by a longer-or-equal
/// earlier-rule span.
///
/// Sort key: (start asc, length desc, rule_idx asc).
/// After sorting, walk forward keeping a `cursor` past the end of the
/// last accepted span. Any span starting before the cursor is discarded.
fn resolve_overlaps(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.rule_idx.cmp(&b.rule_idx))
    });
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    let mut cursor: usize = 0;
    for s in spans {
        if s.start < cursor {
            continue;
        }
        cursor = s.end;
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ContentTypeMode, RawConfig, RawRule};
    use crate::mask::seed_from;

    fn cfg_with(rules: Vec<RawRule>) -> PolicyConfig {
        PolicyConfig::from_raw(RawConfig {
            mask_request_body: true,
            unmask_response_body: true,
            content_type_mode: Some("auto".into()),
            max_body_size_bytes: None,
            max_vault_entries: None,
            rules,
        })
        .unwrap()
    }

    fn vault() -> Vault {
        Vault::new(seed_from(b"matcher-test"), 1000)
    }

    #[test]
    fn ssn_in_text_is_masked_and_enrolled() {
        let cfg = cfg_with(vec![RawRule {
            name: "ssn".into(),
            rule_type: "builtin".into(),
            builtin_pattern: Some("GovernmentId/UsSsn".into()),
            custom_regex: None,
            data_type: Some("number".into()),
            values: vec![],
            scope: None,
        }]);
        let _ = ContentTypeMode::Auto; // silence unused
        let mut v = vault();
        let masked = mask_request("SSN: 123-45-6789.", &cfg, &mut v);
        assert!(!masked.contains("123-45-6789"));
        assert_eq!(v.len(), 1, "scope=both should enroll");
    }

    #[test]
    fn static_list_masks_each_match() {
        let cfg = cfg_with(vec![RawRule {
            name: "names".into(),
            rule_type: "static".into(),
            builtin_pattern: None,
            custom_regex: None,
            data_type: Some("name".into()),
            values: vec!["Amir Khan".into(), "Johan Koeppel".into()],
            scope: None,
        }]);
        let mut v = vault();
        let out = mask_request("Customers Amir Khan and Johan Koeppel are loyal.", &cfg, &mut v);
        assert!(!out.contains("Amir Khan"));
        assert!(!out.contains("Johan Koeppel"));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn longest_match_wins_on_overlap() {
        // Rule A matches "abcdef", rule B matches "cd". A starts earlier
        // and is longer — should win.
        let cfg = cfg_with(vec![
            RawRule {
                name: "a".into(),
                rule_type: "static".into(),
                builtin_pattern: None,
                custom_regex: None,
                data_type: None,
                values: vec!["abcdef".into()],
                scope: None,
            },
            RawRule {
                name: "b".into(),
                rule_type: "static".into(),
                builtin_pattern: None,
                custom_regex: None,
                data_type: None,
                values: vec!["cd".into()],
                scope: None,
            },
        ]);
        let mut v = vault();
        let out = mask_request("xx abcdef yy", &cfg, &mut v);
        assert!(!out.contains("abcdef"));
        assert!(!out.contains("cd"));
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn same_value_twice_uses_same_mask() {
        let cfg = cfg_with(vec![RawRule {
            name: "ssn".into(),
            rule_type: "builtin".into(),
            builtin_pattern: Some("GovernmentId/UsSsn".into()),
            custom_regex: None,
            data_type: Some("number".into()),
            values: vec![],
            scope: None,
        }]);
        let mut v = vault();
        let out = mask_request("123-45-6789 then 123-45-6789", &cfg, &mut v);
        assert_eq!(v.len(), 1);
        // The mask should appear twice in the output.
        let mask = &v.entries()[0].0;
        assert_eq!(out.matches(mask.as_str()).count(), 2);
    }

    #[test]
    fn scope_request_does_not_enroll() {
        let cfg = cfg_with(vec![RawRule {
            name: "ssn".into(),
            rule_type: "builtin".into(),
            builtin_pattern: Some("GovernmentId/UsSsn".into()),
            custom_regex: None,
            data_type: Some("number".into()),
            values: vec![],
            scope: Some("request".into()),
        }]);
        let mut v = vault();
        let _ = mask_request("SSN 123-45-6789", &cfg, &mut v);
        assert!(v.is_empty(), "scope=request should mask but not enroll");
    }
}
