use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedBundle {
  pub version: u32,
  pub bundle_id: String,
  pub created_at: u64,
  pub rules_version: u64,
  pub reputation: ReputationLists,
  pub rules: Vec<RuleOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationLists {
  #[serde(default)]
  pub domains_block: Vec<String>,
  #[serde(default)]
  pub hashes_block: Vec<String>,
  #[serde(default)]
  pub wallet_spenders_block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
  pub rule_id: String,
  pub enabled: bool,
  pub severity_floor: BundleSeverity,
  pub severity_cap_learning: BundleSeverity,
  pub severity_strict: BundleSeverity,
  #[serde(default)]
  pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BundleSeverity {
  Green,
  Yellow,
  Red,
}
