use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct MaskingRules0Config {
    #[serde(alias = "builtinPattern")]
    pub builtin_pattern: Option<String>,
    #[serde(alias = "customRegex")]
    pub custom_regex: Option<String>,
    #[serde(alias = "dataType")]
    pub data_type: Option<String>,
    #[serde(alias = "name")]
    pub name: String,
    #[serde(alias = "ruleType")]
    pub rule_type: String,
    #[serde(alias = "scope")]
    pub scope: Option<String>,
    #[serde(alias = "values")]
    pub values: Option<Vec<String>>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "contentTypeMode")]
    pub content_type_mode: Option<String>,
    #[serde(alias = "maskRequestBody")]
    pub mask_request_body: Option<bool>,
    #[serde(alias = "maskingRules")]
    pub masking_rules: Option<Vec<MaskingRules0Config>>,
    #[serde(alias = "maxBodySizeBytes")]
    pub max_body_size_bytes: Option<i64>,
    #[serde(alias = "maxVaultEntries")]
    pub max_vault_entries: Option<i64>,
    #[serde(alias = "unmaskResponseBody")]
    pub unmask_response_body: Option<bool>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
