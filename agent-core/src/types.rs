use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
  Green,
  Yellow,
  Red,
}

pub type RuleId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
  ProcessStart {
    pid: u32,
    ppid: u32,
    image_path: String,
    signer_publisher: Option<String>,
    timestamp_unix_ms: u64,
  },
  FileAccess {
    pid: u32,
    image_path: Option<String>,
    file_path: String,
    access: FileAccessType,
    timestamp_unix_ms: u64,
  },
  NetConnect {
    pid: u32,
    image_path: Option<String>,
    dest_ip: String,
    dest_port: u16,
    dest_host: Option<String>,
    protocol: String,
    timestamp_unix_ms: u64,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileAccessType {
  Read,
  Write,
  Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
  Process {
    pid: u32,
    ppid: u32,
    image_path: String,
    signer_publisher: Option<String>,
  },
  File {
    pid: u32,
    image_path: Option<String>,
    file_path: String,
    access: FileAccessType,
  },
  Network {
    pid: u32,
    image_path: Option<String>,
    dest_ip: String,
    dest_port: u16,
    dest_host: Option<String>,
    protocol: String,
  },
  Correlation {
    pid: u32,
    window_seconds: u64,
    sensitive_file: String,
    dest_ip: String,
    dest_host: Option<String>,
    delta_seconds: u64,
  },
  Note {
    message: String,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
  pub rule_id: RuleId,
  pub severity: Severity,
  pub description: String,
  pub evidence: Vec<Evidence>,
  pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
  pub incident_id: String,
  pub severity: Severity,
  pub findings: Vec<Finding>,
  pub actions_taken: Vec<String>,
  pub created_at_unix_ms: u64,
}

impl Incident {
  pub fn new(findings: Vec<Finding>) -> Self {
    let severity = max_severity(findings.iter().map(|f| f.severity));
    Self {
      incident_id: uuid::Uuid::new_v4().to_string(),
      severity,
      findings,
      actions_taken: Vec::new(),
      created_at_unix_ms: now_unix_ms(),
    }
  }

  pub fn max_severity(&self) -> Severity {
    max_severity(self.findings.iter().map(|f| f.severity))
  }
}

fn max_severity(severities: impl Iterator<Item = Severity>) -> Severity {
  severities
    .max_by_key(|s| match s {
      Severity::Green => 0,
      Severity::Yellow => 1,
      Severity::Red => 2,
    })
    .unwrap_or(Severity::Green)
}

pub fn redact_path_for_log(path: &str) -> String {
  // Never log contents; paths are generally safe but can contain user identifiers.
  // For logs, prefer only the filename component to reduce leakage.
  std::path::Path::new(path)
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("<redacted>")
    .to_string()
}

pub fn now_unix_ms() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as u64
}
