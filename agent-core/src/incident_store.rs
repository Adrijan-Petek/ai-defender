use crate::paths;
use crate::runtime;
use crate::types::{Incident, Severity};
use std::fs;
use std::path::{Path, PathBuf};

pub fn store_incident(incident: &Incident) -> anyhow::Result<PathBuf> {
  let base = paths::base_dir()?;
  let dir = paths::incidents_dir(&base);
  let file_path = dir.join(format!("{}.toml", incident.incident_id));

  if runtime::is_dry_run() {
    tracing::warn!(
      incident_id = %incident.incident_id,
      severity = ?incident.severity,
      "DRY-RUN: would store incident record"
    );
    return Ok(file_path);
  }

  fs::create_dir_all(&dir)?;

  let raw = toml::to_string_pretty(incident)?;
  write_atomic(&file_path, &raw)?;
  Ok(file_path)
}

#[derive(Debug, Clone)]
pub struct IncidentSummary {
  pub incident_id: String,
  pub created_at_unix_ms: u64,
  pub severity: Severity,
  pub rule_ids: Vec<String>,
}

pub fn list_recent(limit: usize) -> anyhow::Result<Vec<IncidentSummary>> {
  let base = paths::base_dir()?;
  let dir = paths::incidents_dir(&base);
  if !dir.exists() {
    return Ok(Vec::new());
  }

  let mut entries: Vec<_> = fs::read_dir(&dir)?
    .flatten()
    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
    .collect();

  entries.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
  entries.reverse();

  let mut out = Vec::new();
  for e in entries.into_iter().take(limit) {
    let raw = match fs::read_to_string(e.path()) {
      Ok(r) => r,
      Err(_) => continue,
    };
    let inc: Incident = match toml::from_str(&raw) {
      Ok(i) => i,
      Err(_) => continue,
    };
    let rule_ids = inc.findings.iter().map(|f| f.rule_id.clone()).collect();
    out.push(IncidentSummary {
      incident_id: inc.incident_id,
      created_at_unix_ms: inc.created_at_unix_ms,
      severity: inc.severity,
      rule_ids,
    });
  }

  Ok(out)
}

fn write_atomic(path: &Path, contents: &str) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("file path has no parent: {}", path.display()))?;
  fs::create_dir_all(parent)?;

  let tmp = parent.join(format!(
    ".{}.tmp",
    path.file_name().unwrap_or_default().to_string_lossy()
  ));
  fs::write(&tmp, contents)?;
  fs::rename(&tmp, path)?;
  Ok(())
}
