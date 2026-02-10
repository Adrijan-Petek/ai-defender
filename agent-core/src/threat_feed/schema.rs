use serde::{Deserialize, Serialize};

// Signed bundle schema (JSON).
//
// This schema is intentionally conservative for v1:
// - versioned
// - explainable
// - offline importable
// - no executable code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedBundle {
  // Monotonically increasing integer version.
  pub version: u64,

  // When the bundle was created (publisher time).
  pub created_at_unix_ms: u64,

  // Human-readable issuer identifier (not a security boundary).
  #[serde(default)]
  pub issuer: Option<String>,

  // Optional notes for operators.
  #[serde(default)]
  pub notes: Option<String>,

  // Rule/reputation payload (no executable code).
  #[serde(default)]
  pub reputation: ReputationPayload,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationPayload {
  // Domain patterns (exact or suffix patterns, interpretation is rule-specific).
  #[serde(default)]
  pub domains: Vec<String>,

  // Hash indicators (format is rule-specific; v1 does not enforce semantics here).
  #[serde(default)]
  pub hashes: Vec<String>,

  // Wallet-drainer patterns or identifiers (format is rule-specific).
  #[serde(default)]
  pub wallet_drain_patterns: Vec<String>,
}

