use crate::config::{AllowlistConfig, Config};
use crate::types::{Evidence, Event, Finding, Incident, Severity};
use super::protected_paths;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
struct ProcessInfo {
  image_path: String,
  signer_publisher: Option<String>,
}

#[derive(Debug, Clone)]
struct SensitiveAccess {
  timestamp_unix_ms: u64,
  file_path: String,
  access: crate::types::FileAccessType,
  target: ProtectedTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedTarget {
  ChromeLoginData,
  ChromeCookies,
  ChromeLocalState,
  FirefoxLoginsJson,
  FirefoxKey4Db,
  FirefoxCookiesSqlite,
}

pub struct Engine {
  procs: HashMap<u32, ProcessInfo>,
  sensitive: HashMap<u32, VecDeque<SensitiveAccess>>,
  enum_hits: HashMap<u32, VecDeque<u64>>,
}

impl Engine {
  pub fn new() -> Self {
    Self {
      procs: HashMap::new(),
      sensitive: HashMap::new(),
      enum_hits: HashMap::new(),
    }
  }

  pub fn process(&mut self, cfg: &Config, events: &[Event]) -> anyhow::Result<Vec<Incident>> {
    let mut incidents = Vec::new();

    for ev in events {
      match ev {
        Event::ProcessStart {
          pid,
          image_path,
          signer_publisher,
          ppid,
          timestamp_unix_ms,
        } => {
          self.procs.insert(
            *pid,
            ProcessInfo {
              image_path: image_path.clone(),
              signer_publisher: signer_publisher.clone(),
            },
          );

          // Placeholder: no detection rules yet on process start.
          let _ = (ppid, timestamp_unix_ms);
        }
        Event::FileAccess {
          pid,
          image_path,
          file_path,
          access,
          timestamp_unix_ms,
        } => {
          self.prune_old(*pid, *timestamp_unix_ms, cfg.correlation_window_seconds);
          self.prune_enum_old(*pid, *timestamp_unix_ms);

          if is_path_allowlisted(&cfg.allowlist, file_path) {
            continue;
          }

          let proc = self.proc_info(*pid, image_path);
          let target = match protected_paths::classify_protected_target(cfg, file_path) {
            Some(t) => t,
            None => continue,
          };

          // Record for correlation regardless of whether we emit a finding.
          self
            .sensitive
            .entry(*pid)
            .or_default()
            .push_back(SensitiveAccess {
              timestamp_unix_ms: *timestamp_unix_ms,
              file_path: file_path.clone(),
              access: *access,
              target,
            });

          if is_browser_self_access(&proc.image_path, target) {
            continue;
          }

          let allowlisted =
            publisher_allowlisted(&cfg.allowlist, proc.signer_publisher.as_deref());

          let mut findings = Vec::new();

          if !allowlisted {
            findings.extend(crate::rules_engine::rules::file_access_rule_findings(
              cfg,
              *pid,
              &proc.image_path,
              file_path,
              *access,
              *timestamp_unix_ms,
              target,
            ));
          }

          if proc
            .signer_publisher
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
            && !allowlisted
          {
            findings.push(Finding {
              rule_id: "R008".to_string(),
              severity: Severity::Yellow,
              description: "Unknown/unsigned publisher touched protected browser target".to_string(),
              evidence: vec![Evidence::Note {
                message: "signer_publisher missing".to_string(),
              }],
              timestamp_unix_ms: *timestamp_unix_ms,
            });
          }

          if protected_paths::is_under_protected_root(file_path) && !allowlisted {
            self
              .enum_hits
              .entry(*pid)
              .or_default()
              .push_back(*timestamp_unix_ms);

            if self.is_enumerating(*pid) {
              findings.push(Finding {
                rule_id: "R007".to_string(),
                severity: Severity::Yellow,
                description: "High-rate enumeration under browser profile directories".to_string(),
                evidence: vec![Evidence::File {
                  pid: *pid,
                  image_path: Some(proc.image_path.clone()),
                  file_path: file_path.to_string(),
                  access: *access,
                }],
                timestamp_unix_ms: *timestamp_unix_ms,
              });
            }
          }

          if !findings.is_empty() {
            incidents.push(Incident::new(findings));
          }
        }
        Event::NetConnect {
          pid,
          image_path,
          dest_ip,
          dest_port,
          dest_host,
          protocol,
          timestamp_unix_ms,
        } => {
          self.prune_old(*pid, *timestamp_unix_ms, cfg.correlation_window_seconds);
          let proc = self.proc_info(*pid, image_path);

          let Some(access) = self
            .sensitive
            .get(pid)
            .and_then(|q| q.back())
            .cloned()
          else {
            continue;
          };

          if is_browser_self_access(&proc.image_path, access.target) {
            continue;
          }

          let allowlisted = publisher_allowlisted(&cfg.allowlist, proc.signer_publisher.as_deref());
          let suspicious = !allowlisted || !is_known_browser_image(&proc.image_path);
          if !suspicious {
            continue;
          }

          let window_ms = cfg.correlation_window_seconds.saturating_mul(1000);
          let delta_ms = timestamp_unix_ms.saturating_sub(access.timestamp_unix_ms);
          if delta_ms > window_ms {
            continue;
          }

          let delta_seconds = delta_ms / 1000;
          let mut findings = Vec::new();
          findings.push(Finding {
            rule_id: "R009".to_string(),
            severity: Severity::Red,
            description: "Sensitive browser data access followed by outbound network connection"
              .to_string(),
            evidence: vec![
              Evidence::File {
                pid: *pid,
                image_path: Some(proc.image_path.clone()),
                file_path: access.file_path.clone(),
                access: access.access,
              },
              Evidence::Network {
                pid: *pid,
                image_path: Some(proc.image_path.clone()),
                dest_ip: dest_ip.clone(),
                dest_port: *dest_port,
                dest_host: dest_host.clone(),
                protocol: protocol.clone(),
              },
              Evidence::Correlation {
                pid: *pid,
                window_seconds: cfg.correlation_window_seconds,
                sensitive_file: access.file_path.clone(),
                dest_ip: dest_ip.clone(),
                dest_host: dest_host.clone(),
                delta_seconds,
              },
            ],
            timestamp_unix_ms: *timestamp_unix_ms,
          });

          if dest_host.as_deref().map(|h| h.trim().is_empty()).unwrap_or(true) {
            findings.push(Finding {
              rule_id: "R010".to_string(),
              severity: Severity::Red,
              description: "Outbound connection after sensitive access to direct IP / unknown host"
                .to_string(),
              evidence: vec![Evidence::Note {
                message: "dest_host missing/empty".to_string(),
              }],
              timestamp_unix_ms: *timestamp_unix_ms,
            });
          }

          incidents.push(Incident::new(findings));
        }
      }
    }

    Ok(incidents)
  }

  fn prune_old(&mut self, pid: u32, now_unix_ms: u64, window_seconds: u64) {
    let window_ms = window_seconds.saturating_mul(1000);
    if let Some(q) = self.sensitive.get_mut(&pid) {
      while let Some(front) = q.front() {
        if now_unix_ms.saturating_sub(front.timestamp_unix_ms) <= window_ms {
          break;
        }
        q.pop_front();
      }
      if q.is_empty() {
        self.sensitive.remove(&pid);
      }
    }
  }

  fn prune_enum_old(&mut self, pid: u32, now_unix_ms: u64) {
    const WINDOW_MS: u64 = 10_000;
    if let Some(q) = self.enum_hits.get_mut(&pid) {
      while let Some(front) = q.front() {
        if now_unix_ms.saturating_sub(*front) <= WINDOW_MS {
          break;
        }
        q.pop_front();
      }
      if q.is_empty() {
        self.enum_hits.remove(&pid);
      }
    }
  }

  fn is_enumerating(&self, pid: u32) -> bool {
    const THRESHOLD: usize = 50;
    self
      .enum_hits
      .get(&pid)
      .map(|q| q.len() >= THRESHOLD)
      .unwrap_or(false)
  }

  fn proc_info(&self, pid: u32, image_path: &Option<String>) -> ProcessInfo {
    if let Some(p) = self.procs.get(&pid) {
      return p.clone();
    }
    ProcessInfo {
      image_path: image_path.clone().unwrap_or_else(|| "<unknown>".to_string()),
      signer_publisher: None,
    }
  }
}

fn publisher_allowlisted(allowlist: &AllowlistConfig, publisher: Option<&str>) -> bool {
  let Some(p) = publisher else { return false };
  let p_norm = p.trim().to_ascii_lowercase();
  allowlist
    .publishers
    .iter()
    .any(|a| a.trim().to_ascii_lowercase() == p_norm)
}

fn is_path_allowlisted(allowlist: &AllowlistConfig, path: &str) -> bool {
  let p = path.to_ascii_lowercase();
  allowlist
    .paths_allowlist
    .iter()
    .filter(|s| !s.trim().is_empty())
    .any(|prefix| p.starts_with(&prefix.trim().to_ascii_lowercase()))
}

fn is_known_browser_image(image_path: &str) -> bool {
  let p = image_path.to_ascii_lowercase();
  p.ends_with("\\chrome.exe")
    || p.ends_with("\\msedge.exe")
    || p.ends_with("\\brave.exe")
    || p.ends_with("\\firefox.exe")
}

fn is_browser_self_access(image_path: &str, _target: ProtectedTarget) -> bool {
  // Conservative: if the accessing process is a known browser, treat its access to its own stores
  // as expected and do not generate findings or correlations.
  is_known_browser_image(image_path)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::types::FileAccessType;

  fn cfg() -> Config {
    Config::default()
  }

  #[test]
  fn correlation_generates_red_within_window() {
    let cfg = cfg();
    let mut eng = Engine::new();
    let pid = 1234;
    let base = 1_700_000_000_000u64;

    let file_path =
      "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data".to_string();

    let events = vec![
      Event::ProcessStart {
        pid,
        ppid: 0,
        image_path: "C:\\Temp\\evil.exe".to_string(),
        signer_publisher: None,
        timestamp_unix_ms: base,
      },
      Event::FileAccess {
        pid,
        image_path: Some("C:\\Temp\\evil.exe".to_string()),
        file_path,
        access: FileAccessType::Read,
        timestamp_unix_ms: base + 1_000,
      },
      Event::NetConnect {
        pid,
        image_path: Some("C:\\Temp\\evil.exe".to_string()),
        dest_ip: "1.2.3.4".to_string(),
        dest_port: 443,
        dest_host: None,
        protocol: "tcp".to_string(),
        timestamp_unix_ms: base + 2_000,
      },
    ];

    let incidents = eng.process(&cfg, &events).unwrap();
    assert!(incidents.iter().any(|i| i.findings.iter().any(|f| f.rule_id == "R009")));
    assert!(incidents.iter().any(|i| i.severity == Severity::Red));
  }

  #[test]
  fn correlation_does_not_fire_outside_window() {
    let mut cfg = cfg();
    cfg.correlation_window_seconds = 1;
    let mut eng = Engine::new();
    let pid = 1234;
    let base = 1_700_000_000_000u64;
    let file_path =
      "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data".to_string();

    let events = vec![
      Event::ProcessStart {
        pid,
        ppid: 0,
        image_path: "C:\\Temp\\evil.exe".to_string(),
        signer_publisher: None,
        timestamp_unix_ms: base,
      },
      Event::FileAccess {
        pid,
        image_path: Some("C:\\Temp\\evil.exe".to_string()),
        file_path,
        access: FileAccessType::Read,
        timestamp_unix_ms: base,
      },
      Event::NetConnect {
        pid,
        image_path: Some("C:\\Temp\\evil.exe".to_string()),
        dest_ip: "1.2.3.4".to_string(),
        dest_port: 443,
        dest_host: None,
        protocol: "tcp".to_string(),
        timestamp_unix_ms: base + 5_000,
      },
    ];

    let incidents = eng.process(&cfg, &events).unwrap();
    assert!(!incidents.iter().any(|i| i.findings.iter().any(|f| f.rule_id == "R009")));
  }

  #[test]
  fn browser_self_access_produces_no_incident() {
    let cfg = cfg();
    let mut eng = Engine::new();
    let pid = 2001;
    let base = 1_700_000_000_000u64;

    let file_path =
      "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data".to_string();

    let events = vec![
      Event::ProcessStart {
        pid,
        ppid: 0,
        image_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string(),
        signer_publisher: Some("Google LLC".to_string()),
        timestamp_unix_ms: base,
      },
      Event::FileAccess {
        pid,
        image_path: Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string()),
        file_path,
        access: FileAccessType::Read,
        timestamp_unix_ms: base + 1_000,
      },
      Event::NetConnect {
        pid,
        image_path: Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string()),
        dest_ip: "1.2.3.4".to_string(),
        dest_port: 443,
        dest_host: Some("example.com".to_string()),
        protocol: "tcp".to_string(),
        timestamp_unix_ms: base + 2_000,
      },
    ];

    let incidents = eng.process(&cfg, &events).unwrap();
    assert!(incidents.is_empty());
  }

  #[test]
  fn allowlisted_publisher_suppresses_findings() {
    let cfg = cfg();
    let mut eng = Engine::new();
    let pid = 3001;
    let base = 1_700_000_000_000u64;

    let file_path =
      "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies".to_string();

    let events = vec![
      Event::ProcessStart {
        pid,
        ppid: 0,
        image_path: "C:\\Temp\\backup-tool.exe".to_string(),
        signer_publisher: Some("  gOoGlE llC  ".to_string()),
        timestamp_unix_ms: base,
      },
      Event::FileAccess {
        pid,
        image_path: Some("C:\\Temp\\backup-tool.exe".to_string()),
        file_path,
        access: FileAccessType::Read,
        timestamp_unix_ms: base + 1_000,
      },
    ];

    let incidents = eng.process(&cfg, &events).unwrap();
    assert!(incidents.is_empty());
  }

  #[test]
  fn publisher_allowlist_normalizes_case_and_whitespace() {
    let a = AllowlistConfig {
      publishers: vec!["Google LLC".to_string()],
      paths_allowlist: vec![],
    };

    assert!(publisher_allowlisted(&a, Some("google llc")));
    assert!(publisher_allowlisted(&a, Some("  GoOgLe LLC  ")));
    assert!(!publisher_allowlisted(&a, Some("Mozilla Corporation")));
    assert!(!publisher_allowlisted(&a, None));
  }
}
