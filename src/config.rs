//! Three-layer config:
//!
//!   codegen `Config` (deserialized from operator-supplied JSON)
//!     -> `RawConfig` (host-testable, no PDK types)
//!     -> `PolicyConfig` (validated, strongly-typed, with compiled rules)
//!
//! Validation runs at policy load via `PolicyConfig::from_raw`. Bad config
//! (unknown built-in pattern name, malformed customRegex, empty static
//! values) fails policy load with a clear error rather than failing
//! per-request.

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use thiserror::Error;

use crate::catalog;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("contentTypeMode must be one of: auto, json, text (got '{0}')")]
    BadContentTypeMode(String),
    #[error("maxBodySizeBytes out of range [1024, 52428800]: {0}")]
    BadMaxBodySize(i64),
    #[error("maxVaultEntries out of range [100, 1000000]: {0}")]
    BadMaxVaultEntries(i64),
    #[error("rule '{0}': ruleType must be one of: builtin, customRegex, static (got '{1}')")]
    BadRuleType(String, String),
    #[error("rule '{0}': scope must be one of: request, response, both (got '{1}')")]
    BadScope(String, String),
    #[error("rule '{0}': dataType must be one of: text, name, email, number, alphanumeric, identifier (got '{1}')")]
    BadDataType(String, String),
    #[error("rule '{0}': builtinPattern '{1}' is not in the catalog")]
    UnknownBuiltin(String, String),
    #[error("rule '{0}': ruleType=builtin requires builtinPattern to be set")]
    MissingBuiltin(String),
    #[error("rule '{0}': ruleType=customRegex requires customRegex to be set")]
    MissingCustomRegex(String),
    #[error("rule '{0}': customRegex failed to compile: {1}")]
    BadCustomRegex(String, String),
    #[error("rule '{0}': built-in pattern '{1}' failed to compile: {2}")]
    BadBuiltinRegex(String, String, String),
    #[error("rule '{0}': ruleType=static requires non-empty values")]
    EmptyStaticValues(String),
    #[error("rule '{0}': static values automaton failed to build: {1}")]
    BadStaticAutomaton(String, String),
}

/// Host-testable raw config, decoupled from the codegen layer.
#[derive(Debug, Clone)]
pub struct RawRule {
    pub name: String,
    pub rule_type: String,
    pub builtin_pattern: Option<String>,
    pub custom_regex: Option<String>,
    pub data_type: Option<String>,
    pub values: Vec<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RawConfig {
    pub mask_request_body: bool,
    pub unmask_response_body: bool,
    pub content_type_mode: Option<String>,
    pub max_body_size_bytes: Option<i64>,
    pub max_vault_entries: Option<i64>,
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentTypeMode {
    Auto,
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Request,
    Response,
    Both,
}

impl Scope {
    pub fn applies_to_request(self) -> bool {
        matches!(self, Scope::Request | Scope::Both)
    }

    pub fn applies_to_response(self) -> bool {
        matches!(self, Scope::Response | Scope::Both)
    }

    /// Only `Both` enrolls into the unmask vault. `Request`-only means the
    /// downstream client should keep seeing the masked form.
    pub fn enrolls_into_vault(self) -> bool {
        matches!(self, Scope::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Text,
    Name,
    Email,
    Number,
    Alphanumeric,
    Identifier,
}

#[derive(Debug, Clone)]
pub enum CompiledRule {
    Regex {
        #[allow(dead_code)] // surfaced via the cfg(test) name() accessor
        name: String,
        regex: regex::Regex,
        scope: Scope,
        data_type: DataType,
    },
    Static {
        #[allow(dead_code)]
        name: String,
        ac: aho_corasick::AhoCorasick,
        scope: Scope,
        data_type: DataType,
    },
}

impl CompiledRule {
    pub fn scope(&self) -> Scope {
        match self {
            CompiledRule::Regex { scope, .. } => *scope,
            CompiledRule::Static { scope, .. } => *scope,
        }
    }

    #[cfg(test)]
    pub fn name(&self) -> &str {
        match self {
            CompiledRule::Regex { name, .. } => name,
            CompiledRule::Static { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub mask_request_body: bool,
    pub unmask_response_body: bool,
    pub content_type_mode: ContentTypeMode,
    pub max_body_size_bytes: usize,
    pub max_vault_entries: usize,
    pub rules: Vec<CompiledRule>,
}

impl PolicyConfig {
    pub fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let content_type_mode = match raw.content_type_mode.as_deref().unwrap_or("auto") {
            "auto" => ContentTypeMode::Auto,
            "json" => ContentTypeMode::Json,
            "text" => ContentTypeMode::Text,
            other => return Err(ConfigError::BadContentTypeMode(other.into())),
        };

        let max_body_size_bytes = match raw.max_body_size_bytes.unwrap_or(5_242_880) {
            v if (1024..=52_428_800).contains(&v) => v as usize,
            v => return Err(ConfigError::BadMaxBodySize(v)),
        };

        let max_vault_entries = match raw.max_vault_entries.unwrap_or(100_000) {
            v if (100..=1_000_000).contains(&v) => v as usize,
            v => return Err(ConfigError::BadMaxVaultEntries(v)),
        };

        let mut rules = Vec::with_capacity(raw.rules.len());
        for r in raw.rules {
            rules.push(compile_rule(r)?);
        }

        Ok(Self {
            mask_request_body: raw.mask_request_body,
            unmask_response_body: raw.unmask_response_body,
            content_type_mode,
            max_body_size_bytes,
            max_vault_entries,
            rules,
        })
    }
}

fn compile_rule(r: RawRule) -> Result<CompiledRule, ConfigError> {
    let scope = match r.scope.as_deref().unwrap_or("both") {
        "request" => Scope::Request,
        "response" => Scope::Response,
        "both" => Scope::Both,
        other => return Err(ConfigError::BadScope(r.name.clone(), other.into())),
    };

    let data_type = match r.data_type.as_deref().unwrap_or("text") {
        "text" => DataType::Text,
        "name" => DataType::Name,
        "email" => DataType::Email,
        "number" => DataType::Number,
        "alphanumeric" => DataType::Alphanumeric,
        "identifier" => DataType::Identifier,
        other => return Err(ConfigError::BadDataType(r.name.clone(), other.into())),
    };

    match r.rule_type.as_str() {
        "builtin" => {
            let builtin = r
                .builtin_pattern
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ConfigError::MissingBuiltin(r.name.clone()))?;
            let pat = catalog::lookup(builtin)
                .ok_or_else(|| ConfigError::UnknownBuiltin(r.name.clone(), builtin.into()))?;
            let regex = regex::Regex::new(pat).map_err(|e| {
                ConfigError::BadBuiltinRegex(r.name.clone(), builtin.into(), e.to_string())
            })?;
            Ok(CompiledRule::Regex {
                name: r.name,
                regex,
                scope,
                data_type,
            })
        }
        "customRegex" => {
            let pat = r
                .custom_regex
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ConfigError::MissingCustomRegex(r.name.clone()))?;
            let regex = regex::Regex::new(pat)
                .map_err(|e| ConfigError::BadCustomRegex(r.name.clone(), e.to_string()))?;
            Ok(CompiledRule::Regex {
                name: r.name,
                regex,
                scope,
                data_type,
            })
        }
        "static" => {
            if r.values.is_empty() {
                return Err(ConfigError::EmptyStaticValues(r.name.clone()));
            }
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .ascii_case_insensitive(false)
                .build(&r.values)
                .map_err(|e| ConfigError::BadStaticAutomaton(r.name.clone(), e.to_string()))?;
            Ok(CompiledRule::Static {
                name: r.name,
                ac,
                scope,
                data_type,
            })
        }
        other => Err(ConfigError::BadRuleType(r.name.clone(), other.into())),
    }
}

/// Bridge codegen `Config` -> `RawConfig`. Lives in this module so the
/// `from_raw` validation pipeline is the single source of truth.
impl From<&crate::generated::config::Config> for RawConfig {
    fn from(c: &crate::generated::config::Config) -> Self {
        RawConfig {
            mask_request_body: c.mask_request_body.unwrap_or(true),
            unmask_response_body: c.unmask_response_body.unwrap_or(true),
            content_type_mode: c.content_type_mode.clone(),
            max_body_size_bytes: c.max_body_size_bytes,
            max_vault_entries: c.max_vault_entries,
            rules: c
                .masking_rules
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|r| RawRule {
                    name: r.name.clone(),
                    rule_type: r.rule_type.clone(),
                    builtin_pattern: r.builtin_pattern.clone(),
                    custom_regex: r.custom_regex.clone(),
                    data_type: r.data_type.clone(),
                    values: r.values.clone().unwrap_or_default(),
                    scope: r.scope.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(rules: Vec<RawRule>) -> RawConfig {
        RawConfig {
            mask_request_body: true,
            unmask_response_body: true,
            content_type_mode: None,
            max_body_size_bytes: None,
            max_vault_entries: None,
            rules,
        }
    }

    fn rule_static(name: &str, values: &[&str]) -> RawRule {
        RawRule {
            name: name.into(),
            rule_type: "static".into(),
            builtin_pattern: None,
            custom_regex: None,
            data_type: None,
            values: values.iter().map(|s| (*s).to_string()).collect(),
            scope: None,
        }
    }

    fn rule_builtin(name: &str, pattern: &str) -> RawRule {
        RawRule {
            name: name.into(),
            rule_type: "builtin".into(),
            builtin_pattern: Some(pattern.into()),
            custom_regex: None,
            data_type: None,
            values: vec![],
            scope: None,
        }
    }

    fn rule_custom(name: &str, regex: &str) -> RawRule {
        RawRule {
            name: name.into(),
            rule_type: "customRegex".into(),
            builtin_pattern: None,
            custom_regex: Some(regex.into()),
            data_type: None,
            values: vec![],
            scope: None,
        }
    }

    #[test]
    fn defaults_apply() {
        let cfg = PolicyConfig::from_raw(raw(vec![])).unwrap();
        assert_eq!(cfg.content_type_mode, ContentTypeMode::Auto);
        assert_eq!(cfg.max_body_size_bytes, 5_242_880);
        assert_eq!(cfg.max_vault_entries, 100_000);
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn builtin_compiles() {
        let cfg = PolicyConfig::from_raw(raw(vec![rule_builtin(
            "ssn",
            "GovernmentId/UsSsn",
        )]))
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name(), "ssn");
        assert_eq!(cfg.rules[0].scope(), Scope::Both);
    }

    #[test]
    fn unknown_builtin_fails() {
        let err = PolicyConfig::from_raw(raw(vec![rule_builtin(
            "x",
            "GovernmentId/Nope",
        )]))
        .unwrap_err();
        match err {
            ConfigError::UnknownBuiltin(name, pat) => {
                assert_eq!(name, "x");
                assert_eq!(pat, "GovernmentId/Nope");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn custom_regex_compiles() {
        let cfg = PolicyConfig::from_raw(raw(vec![rule_custom(
            "cn",
            r"\bCN-\d{4}\b",
        )]))
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
    }

    #[test]
    fn bad_custom_regex_fails_at_load() {
        let err = PolicyConfig::from_raw(raw(vec![rule_custom("cn", "(unclosed")]))
            .unwrap_err();
        assert!(matches!(err, ConfigError::BadCustomRegex(..)));
    }

    #[test]
    fn empty_static_values_fails() {
        let err = PolicyConfig::from_raw(raw(vec![rule_static("names", &[])]))
            .unwrap_err();
        assert!(matches!(err, ConfigError::EmptyStaticValues(..)));
    }

    #[test]
    fn static_compiles_with_thousands_of_entries() {
        let names: Vec<String> = (0..10_000).map(|i| format!("Name{i:05}")).collect();
        let rule = RawRule {
            name: "many".into(),
            rule_type: "static".into(),
            builtin_pattern: None,
            custom_regex: None,
            data_type: None,
            values: names,
            scope: None,
        };
        let cfg = PolicyConfig::from_raw(raw(vec![rule])).unwrap();
        assert_eq!(cfg.rules.len(), 1);
    }

    #[test]
    fn scope_parsing() {
        let mut r = rule_builtin("e", "Contact/Email");
        r.scope = Some("request".into());
        let cfg = PolicyConfig::from_raw(raw(vec![r])).unwrap();
        assert_eq!(cfg.rules[0].scope(), Scope::Request);
        assert!(cfg.rules[0].scope().applies_to_request());
        assert!(!cfg.rules[0].scope().applies_to_response());
        assert!(!cfg.rules[0].scope().enrolls_into_vault());
    }
}
