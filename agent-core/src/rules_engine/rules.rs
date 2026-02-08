use crate::config::{Config, Mode};
use crate::rules_engine::engine::ProtectedTarget;
use crate::types::{Evidence, FileAccessType, Finding, Severity};

// These rules are currently used for learning, tuning, and logging only.
// In learning mode, their severity is capped at YELLOW and they never trigger containment.

pub const ACTIVE_RULE_IDS: &[&str] = &["R001", "R002", "R003", "R004", "R005"];

#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
  pub id: &'static str,
  pub title: &'static str,
  pub default_severity: Severity,
}

pub const R001: RuleMeta = RuleMeta {
  id: "R001",
  title: "Non-browser process reads Chromium Login Data",
  default_severity: Severity::Yellow,
};
pub const R002: RuleMeta = RuleMeta {
  id: "R002",
  title: "Non-browser process reads Chromium Cookies",
  default_severity: Severity::Yellow,
};
pub const R003: RuleMeta = RuleMeta {
  id: "R003",
  title: "Non-browser process reads Chromium Local State",
  default_severity: Severity::Yellow,
};
pub const R004: RuleMeta = RuleMeta {
  id: "R004",
  title: "Non-browser process reads Firefox logins.json",
  default_severity: Severity::Yellow,
};
pub const R005: RuleMeta = RuleMeta {
  id: "R005",
  title: "Non-browser process reads Firefox key4.db",
  default_severity: Severity::Yellow,
};

pub fn file_access_rule_findings(
  cfg: &Config,
  pid: u32,
  image_path: &str,
  file_path: &str,
  access: FileAccessType,
  ts: u64,
  target: ProtectedTarget,
) -> Vec<Finding> {
  let mut out = Vec::new();

  let (meta, description) = match target {
    ProtectedTarget::ChromeLoginData => (
      R001,
      "Non-browser process accessed Chromium Login Data (learning only)",
    ),
    ProtectedTarget::ChromeCookies => (
      R002,
      "Non-browser process accessed Chromium Cookies (learning only)",
    ),
    ProtectedTarget::ChromeLocalState => (
      R003,
      "Non-browser process accessed Chromium Local State (learning only)",
    ),
    ProtectedTarget::FirefoxLoginsJson => (
      R004,
      "Non-browser process accessed Firefox logins.json (learning only)",
    ),
    ProtectedTarget::FirefoxKey4Db => (
      R005,
      "Non-browser process accessed Firefox key4.db (learning only)",
    ),
    _ => return out,
  };

  let severity = cap_for_learning(cfg, meta.default_severity);
  out.push(Finding {
    rule_id: meta.id.to_string(),
    severity,
    description: description.to_string(),
    evidence: vec![Evidence::File {
      pid,
      image_path: Some(image_path.to_string()),
      file_path: file_path.to_string(),
      access,
    }],
    timestamp_unix_ms: ts,
  });

  out
}

fn cap_for_learning(cfg: &Config, sev: Severity) -> Severity {
  if cfg.mode == Mode::Learning {
    Severity::Yellow
  } else {
    sev
  }
}

