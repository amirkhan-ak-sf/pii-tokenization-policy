//! Hand-written placeholder mirroring what `cargo anypoint config-gen`
//! produces from `definition/gcl.yaml`. `make build` overwrites this with
//! the real codegen output. The shapes must stay aligned.

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct MaskingRules0Config {
    #[serde(alias = "name")]
    pub name: String,
    #[serde(alias = "type")]
    pub r#type: String,
    #[serde(alias = "builtinPattern", default)]
    pub builtin_pattern: Option<String>,
    #[serde(alias = "customRegex", default)]
    pub custom_regex: Option<String>,
    #[serde(alias = "dataType", default)]
    pub data_type: Option<String>,
    #[serde(alias = "values", default)]
    pub values: Option<Vec<String>>,
    #[serde(alias = "scope", default)]
    pub scope: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "maskRequestBody", default)]
    pub mask_request_body: Option<bool>,
    #[serde(alias = "unmaskResponseBody", default)]
    pub unmask_response_body: Option<bool>,
    #[serde(alias = "contentTypeMode", default)]
    pub content_type_mode: Option<String>,
    #[serde(alias = "maxBodySizeBytes", default)]
    pub max_body_size_bytes: Option<i64>,
    #[serde(alias = "maxVaultEntries", default)]
    pub max_vault_entries: Option<i64>,
    #[serde(alias = "maskingRules", default)]
    pub masking_rules: Option<Vec<MaskingRules0Config>>,
}
