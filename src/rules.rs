use reqwest::Method;
use serde::de::{self, MapAccess, SeqAccess, Visitor}; // Added MapAccess
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;
use std::marker::PhantomData;
use tracing::{debug, info};

use super::error::WazuhApiError;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: u32,
    pub level: u32,
    pub description: String,
    pub filename: String,
    pub relative_dirname: String,
    pub status: String,
    pub details: Option<RuleDetails>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub gdpr: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub gpg13: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub hipaa: Option<Vec<String>>,
    #[serde(
        default,
        rename = "nist-800-53",
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub nist_800_53: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub tsc: Option<Vec<String>>,
    #[serde(
        default,
        rename = "pci_dss",
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub pci_dss: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub mitre: Option<Vec<String>>,
    // It needs a deserializer that can turn an empty map {} into an empty Vec.
    #[serde(deserialize_with = "deserialize_vec_or_empty_map_as_vec")]
    pub groups: Vec<String>,
}

fn deserialize_vec_or_empty_map_as_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecOrEmptyMapToVecVisitor(PhantomData<Vec<String>>);

    impl<'de> Visitor<'de> for VecOrEmptyMapToVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a list of strings or an empty map")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(element) = seq.next_element()? {
                vec.push(element);
            }
            Ok(vec)
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            // If it's a map, check if it's empty. If so, treat as an empty Vec.
            // Otherwise, it's an error as a non-empty map cannot be Vec<String>.
            if map.next_key::<String>()?.is_none() {
                Ok(Vec::new()) // Empty map `{}` becomes `vec![]`
            } else {
                Err(de::Error::invalid_type(de::Unexpected::Map, &self))
            }
        }
    }

    deserializer.deserialize_any(VecOrEmptyMapToVecVisitor(PhantomData))
}

// Helper function to deserialize Option<Vec<String>> that might also be an empty map {}
fn deserialize_vec_or_empty_map_as_option_vec<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecOrEmptyMapVisitor(PhantomData<Option<Vec<String>>>);

    impl<'de> Visitor<'de> for VecOrEmptyMapVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a list of strings, null, or an empty map")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(element) = seq.next_element()? {
                vec.push(element);
            }
            Ok(Some(vec)) // Handles `[]` as `Some([])`
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            // Iterate through the map to consume all its entries.
            // This makes the deserializer treat any map (empty or non-empty) as None.
            // This is a lenient approach. If a non-empty map contains valuable data
            // that should be parsed, this approach would discard it.
            // However, it prevents deserialization errors if the API unexpectedly sends a map.
            while let Some(_key) = map.next_key::<serde_json::Value>()? {
                // Consume the value associated with the key
                let _ = map.next_value::<serde_json::Value>()?;
            }
            Ok(None) // Treat any map (empty or non-empty) as None
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None) // Handles `null` as `None`
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None) // Handles omitted field if #[serde(default)] is used
        }
    }

    deserializer.deserialize_any(VecOrEmptyMapVisitor(PhantomData))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatternDetail {
    pub pattern: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfoDetail {
    pub name: String,
    #[serde(rename = "type")]
    pub type_info: String,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec(PhantomData<Vec<String>>);

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                Ok(None) // Treat empty string as None, or Some(vec![]) if preferred
            } else {
                Ok(Some(vec![value.to_owned()]))
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(vec![value]))
            }
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(element) = seq.next_element()? {
                vec.push(element);
            }
            if vec.is_empty() {
                Ok(None)
            } else {
                Ok(Some(vec))
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        // Handles cases like `[]` if the API sends an empty array for an optional field.
        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrVec(PhantomData))
}

fn deserialize_empty_string_as_none_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EmptyStringAsNoneBool(PhantomData<Option<bool>>);

    impl<'de> Visitor<'de> for EmptyStringAsNoneBool {
        type Value = Option<bool>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a boolean or an empty string")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                Ok(None)
            } else {
                // Attempt to parse string "true" or "false" if API might send that
                match value.to_lowercase().as_str() {
                    "true" => Ok(Some(true)),
                    "false" => Ok(Some(false)),
                    _ => Err(de::Error::invalid_value(de::Unexpected::Str(value), &self)),
                }
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                Ok(None)
            } else {
                match value.to_lowercase().as_str() {
                    "true" => Ok(Some(true)),
                    "false" => Ok(Some(false)),
                    _ => Err(de::Error::invalid_value(de::Unexpected::Str(&value), &self)),
                }
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None) // Also treat unit as None, e.g. if API sends `null`
        }
    }

    deserializer.deserialize_any(EmptyStringAsNoneBool(PhantomData))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleDetails {
    pub category: Option<String>,
    pub if_sid: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub if_group: Option<Vec<String>>,
    #[serde(rename = "match")]
    pub match_obj: Option<PatternDetail>, 
    #[serde(rename = "regex")]
    pub regex_obj: Option<PatternDetail>, 
    pub order: Option<String>,
    pub frequency: Option<String>, 
    pub timeframe: Option<String>, 
    pub ignore: Option<String>,
    #[serde(default, deserialize_with = "deserialize_empty_string_as_none_bool")]
    pub check_diff: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_vec_or_empty_map_as_option_vec"
    )]
    pub group: Option<Vec<String>>,
    pub info: Option<Value>, 
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub options: Option<Vec<String>>,
    #[serde(rename = "level")]
    pub level_detail: Option<PatternDetail>,
    pub alert_type: Option<PatternDetail>,
    pub fim_db_table: Option<PatternDetail>,
    pub status: Option<PatternDetail>, 
    pub action: Option<PatternDetail>, 
    #[serde(rename = "id")]
    pub id_detail: Option<PatternDetail>, 
    #[serde(rename = "cisco.severity")]
    pub cisco_severity_detail: Option<PatternDetail>,
    #[serde(rename = "win.system.severityValue")]
    pub win_system_severity_value_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.targetSid")]
    pub win_eventdata_target_sid_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.failureCode")]
    pub win_eventdata_failure_code_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.image")]
    pub win_eventdata_image_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.parentImage")]
    pub win_eventdata_parent_image_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.originalFileName")]
    pub win_eventdata_original_filename_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.commandLine")]
    pub win_eventdata_commandline_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.type")]
    pub win_eventdata_type_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.destination")]
    pub win_eventdata_destination_detail: Option<PatternDetail>,
    #[serde(rename = "win.system.message")]
    pub win_system_message_detail: Option<PatternDetail>,
    #[serde(rename = "win.eventdata.scriptBlockText")]
    pub win_eventdata_scriptblocktext_detail: Option<PatternDetail>,
    #[serde(rename = "Severity")]
    pub severity_detail: Option<PatternDetail>, 
    pub appcat: Option<PatternDetail>,
    pub pri: Option<PatternDetail>, 
    #[serde(rename = "audit.type")]
    pub audit_type_detail: Option<PatternDetail>,
    #[serde(rename = "audit.res")]
    pub audit_res_detail: Option<PatternDetail>,
    #[serde(rename = "event.code")]
    pub event_code_detail: Option<PatternDetail>,
    #[serde(rename = "cs4Label")]
    pub cs4label_detail: Option<PatternDetail>,
    #[serde(rename = "cs4")]
    pub cs4_detail: Option<PatternDetail>,
    #[serde(rename = "cn3Label")]
    pub cn3label_detail: Option<PatternDetail>,
    #[serde(rename = "cn3")]
    pub cn3_detail: Option<PatternDetail>,
    #[serde(rename = "office365.RecordType")]
    pub office365_recordtype_detail: Option<PatternDetail>,
    #[serde(rename = "office365.Operation")]
    pub office365_operation_detail: Option<PatternDetail>,
    #[serde(rename = "office365.Parameters")]
    pub office365_parameters_detail: Option<PatternDetail>, 
    #[serde(rename = "github.action")]
    pub github_action_detail: Option<PatternDetail>,
    #[serde(rename = "vuls.score")]
    pub vuls_score_detail: Option<PatternDetail>,
    #[serde(rename = "vulnerability.status")]
    pub vulnerability_status_detail: Option<PatternDetail>,
    #[serde(rename = "vulnerability.severity")]
    pub vulnerability_severity_detail: Option<PatternDetail>,
    #[serde(rename = "qualysguard.severity")]
    pub qualysguard_severity_detail: Option<PatternDetail>,
    #[serde(rename = "virustotal.malicious")]
    pub virustotal_malicious_detail: Option<PatternDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Decoder {
    pub name: String,
    pub filename: String,
    pub relative_dirname: String,
    pub status: String,
    pub position: Option<u32>, 
    pub details: Option<DecoderDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecoderPatternDetail {
    pub pattern: String,
    pub offset: Option<String>,
    #[serde(rename = "type")]
    pub type_info: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecoderDetails {
    pub program_name: Option<String>,
    pub order: Option<String>,                  
    pub prematch: Option<DecoderPatternDetail>, 
    pub regex: Option<DecoderPatternDetail>,    
    pub parent: Option<String>,
    pub use_own_name: Option<bool>,
    pub json_null_field: Option<String>,
    pub plugin_decoder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RulesClient {
    api_client: WazuhApiClient,
}

impl RulesClient {
    pub fn new(api_client: WazuhApiClient) -> Self {
        Self { api_client }
    }

    pub async fn get_rules(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
        level: Option<u32>,
        group: Option<&str>,
        filename: Option<&str>,
    ) -> Result<Vec<Rule>, WazuhApiError> {
        debug!("Getting rules list");

        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query_params.push(("offset", offset.to_string()));
        }
        if let Some(level) = level {
            query_params.push(("level", level.to_string()));
        }
        if let Some(group) = group {
            query_params.push(("group", group.to_string()));
        }
        if let Some(filename) = filename {
            query_params.push(("filename", filename.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/rules",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let rules_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in rules response".to_string(),
                )
            })?;

        let rules: Vec<Rule> = serde_json::from_value(rules_data.clone())?;
        info!("Retrieved {} rules", rules.len());
        Ok(rules)
    }

    pub async fn get_rule(&mut self, rule_id: u32) -> Result<Rule, WazuhApiError> {
        debug!(%rule_id, "Getting specific rule");

        let rule_id_str = rule_id.to_string();
        let query_params = [("rule_ids", rule_id_str.as_str())];
        let response = self
            .api_client
            .make_request(Method::GET, "/rules", None, Some(&query_params))
            .await?;

        let rule_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| WazuhApiError::ApiError(format!("Rule {} not found", rule_id)))?;

        let rule: Rule = serde_json::from_value(rule_data.clone())?;
        info!(%rule_id, "Retrieved rule details");
        Ok(rule)
    }

    pub async fn get_rules_by_level(&mut self, level: u32) -> Result<Vec<Rule>, WazuhApiError> {
        debug!(%level, "Getting rules by level");
        self.get_rules(None, None, Some(level), None, None).await
    }

    pub async fn get_rules_by_group(&mut self, group: &str) -> Result<Vec<Rule>, WazuhApiError> {
        debug!(%group, "Getting rules by group");
        self.get_rules(None, None, None, Some(group), None).await
    }

    pub async fn get_high_level_rules(&mut self) -> Result<Vec<Rule>, WazuhApiError> {
        debug!("Getting high-level rules");

        let query_params = [("level", "10-15")];
        let response = self
            .api_client
            .make_request(Method::GET, "/rules", None, Some(&query_params))
            .await?;

        let rules_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in high-level rules response".to_string(),
                )
            })?;

        let rules: Vec<Rule> = serde_json::from_value(rules_data.clone())?;
        info!("Retrieved {} high-level rules", rules.len());
        Ok(rules)
    }

    pub async fn get_rule_groups(&mut self) -> Result<Vec<String>, WazuhApiError> {
        debug!("Getting rule groups");

        let response = self
            .api_client
            .make_request(Method::GET, "/rules/groups", None, None)
            .await?;

        let groups_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in rule groups response".to_string(),
                )
            })?;

        let groups: Vec<String> = serde_json::from_value(groups_data.clone())?;
        info!("Retrieved {} rule groups", groups.len());
        Ok(groups)
    }

    pub async fn get_decoders(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
        filename: Option<&str>,
    ) -> Result<Vec<Decoder>, WazuhApiError> {
        debug!("Getting decoders list");

        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query_params.push(("offset", offset.to_string()));
        }
        if let Some(filename) = filename {
            query_params.push(("filename", filename.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/decoders",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let decoders_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in decoders response".to_string(),
                )
            })?;

        let decoders: Vec<Decoder> = serde_json::from_value(decoders_data.clone())?;
        info!("Retrieved {} decoders", decoders.len());
        Ok(decoders)
    }

    pub async fn get_decoder(&mut self, decoder_name: &str) -> Result<Decoder, WazuhApiError> {
        debug!(%decoder_name, "Getting specific decoder");

        let query_params = [("decoder_names", decoder_name)];
        let response = self
            .api_client
            .make_request(Method::GET, "/decoders", None, Some(&query_params))
            .await?;

        let decoder_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError(format!("Decoder {} not found", decoder_name))
            })?;

        let decoder: Decoder = serde_json::from_value(decoder_data.clone())?;
        info!(%decoder_name, "Retrieved decoder details");
        Ok(decoder)
    }

    pub async fn search_rules(&mut self, search_term: &str) -> Result<Vec<Rule>, WazuhApiError> {
        debug!(%search_term, "Searching rules by description");

        let query_params = [("search", search_term)];
        let response = self
            .api_client
            .make_request(Method::GET, "/rules", None, Some(&query_params))
            .await?;

        let rules_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in search rules response".to_string(),
                )
            })?;

        let rules: Vec<Rule> = serde_json::from_value(rules_data.clone())?;
        info!(%search_term, "Found {} rules matching search", rules.len());
        Ok(rules)
    }
}
