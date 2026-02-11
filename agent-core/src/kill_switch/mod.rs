use crate::config::Config;
use crate::paths;
use crate::runtime;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const FIREWALL_RULE_GROUP: &str = "AI_DEFENDER_KILLSWITCH";

pub(super) const RULE_OUT_NAME: &str = "AI Defender KillSwitch Outbound";
pub(super) const RULE_IN_NAME: &str = "AI Defender KillSwitch Inbound";

mod firewall;
pub use firewall::FirewallBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSwitchMode {
  Manual,
  AutoRedOnly,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KillSwitchState {
  #[serde(default)]
  enabled: bool,

  #[serde(default)]
  keep_locked: bool,

  #[serde(default)]
  enabled_mode: Option<KillSwitchMode>,

  #[serde(default)]
  enabled_at_unix_ms: Option<u64>,

  #[serde(default)]
  failsafe_deadline_unix_ms: Option<u64>,

  #[serde(default)]
  last_incident_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KillSwitchStatus {
  pub enabled: bool,
  pub rules_present: bool,
  pub firewall_backend: Option<FirewallBackend>,
  pub keep_locked: bool,
  pub enabled_mode: Option<KillSwitchMode>,
  pub enabled_at_unix_ms: Option<u64>,
  pub failsafe_deadline_unix_ms: Option<u64>,
  pub last_incident_id: Option<String>,
}

pub fn reconcile_on_startup(cfg: &Config) -> anyhow::Result<()> {
  if !cfg.killswitch.enabled {
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      "killswitch disabled by config; ensuring firewall rules are removed"
    );
    let _ = disable_with_reason("config_disabled_cleanup", None);
    return Ok(());
  }

  let base = paths::base_dir()?;
  let state_path = paths::killswitch_state_path(&base);
  let state = load_state_or_default(&state_path);
  let (rules_present, backend) = match firewall::rules_status() {
    Ok(s) => (s.outbound_ok && s.inbound_ok, Some(s.backend)),
    Err(e) => {
      tracing::error!(error = ?e, "startup reconcile: unable to query firewall rules");
      (false, None)
    }
  };

  if !state.enabled && rules_present {
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      "startup reconcile: state says OFF but rules exist; cleaning up"
    );
    let _ = disable_with_reason("startup_cleanup", None);
    return Ok(());
  }

  if state.enabled {
    if should_auto_restore(&state) {
      tracing::warn!(
        group = FIREWALL_RULE_GROUP,
        "startup reconcile: auto failsafe expired; restoring network"
      );
      disable_with_reason("failsafe_startup", state.last_incident_id.as_deref())?;
      return Ok(());
    }

    if !rules_present {
      if runtime::is_dry_run() {
        tracing::warn!(
          group = FIREWALL_RULE_GROUP,
          "DRY-RUN: would re-enable firewall kill switch rules to match persisted ON state"
        );
        return Ok(());
      }
      tracing::warn!(
        group = FIREWALL_RULE_GROUP,
        "startup reconcile: state says ON but rules missing; re-enabling"
      );
      let backend = firewall::enable_rules()?;
      tracing::warn!(
        group = FIREWALL_RULE_GROUP,
        backend = ?backend,
        reason = "startup_reapply",
        timestamp_unix_ms = now_unix_ms(),
        "kill switch rules re-applied"
      );
    }
  }

  if let Some(b) = backend {
    tracing::info!(backend = ?b, "startup reconcile complete");
  }

  Ok(())
}

pub fn status() -> anyhow::Result<KillSwitchStatus> {
  let base = paths::base_dir()?;
  let state_path = paths::killswitch_state_path(&base);
  let state = load_state_or_default(&state_path);
  let fw = firewall::rules_status()?;
  let rules_present = fw.outbound_ok && fw.inbound_ok;

  Ok(KillSwitchStatus {
    enabled: state.enabled,
    rules_present,
    firewall_backend: Some(fw.backend),
    keep_locked: state.keep_locked,
    enabled_mode: state.enabled_mode,
    enabled_at_unix_ms: state.enabled_at_unix_ms,
    failsafe_deadline_unix_ms: state.failsafe_deadline_unix_ms,
    last_incident_id: state.last_incident_id,
  })
}

pub fn set_keep_locked(keep_locked: bool) -> anyhow::Result<()> {
  if runtime::is_dry_run() {
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      keep_locked,
      "DRY-RUN: would update kill switch keep_locked setting"
    );
    return Ok(());
  }

  let base = paths::base_dir()?;
  let state_path = paths::killswitch_state_path(&base);
  let mut state = load_state_or_default(&state_path);
  state.keep_locked = keep_locked;
  save_state(&state_path, &state)?;

  tracing::info!(
    group = FIREWALL_RULE_GROUP,
    keep_locked,
    timestamp_unix_ms = now_unix_ms(),
    "kill switch keep_locked updated"
  );
  Ok(())
}

pub fn enable_manual() -> anyhow::Result<()> {
  if runtime::is_dry_run() {
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      "DRY-RUN: would enable firewall kill switch (group AI_DEFENDER_KILLSWITCH)"
    );
    return Ok(());
  }

  let base = paths::base_dir()?;
  fs::create_dir_all(&base)?;

  let state_path = paths::killswitch_state_path(&base);
  let mut state = load_state_or_default(&state_path);

  let backend = firewall::enable_rules()?;
  state.enabled = true;
  state.enabled_mode = Some(KillSwitchMode::Manual);
  state.enabled_at_unix_ms = Some(now_unix_ms());
  state.failsafe_deadline_unix_ms = None;
  state.last_incident_id = None;
  save_state(&state_path, &state)?;

  tracing::warn!(
    group = FIREWALL_RULE_GROUP,
    backend = ?backend,
    reason = "manual",
    timestamp_unix_ms = state.enabled_at_unix_ms.unwrap_or_default(),
    "kill switch enabled"
  );

  Ok(())
}

pub fn enable_auto(incident_id: &str, failsafe_minutes: u64) -> anyhow::Result<()> {
  if runtime::is_dry_run() {
    tracing::warn!(
      incident_id = %incident_id,
      group = FIREWALL_RULE_GROUP,
      failsafe_minutes,
      "DRY-RUN: would enable firewall kill switch (group AI_DEFENDER_KILLSWITCH)"
    );
    return Ok(());
  }

  let base = paths::base_dir()?;
  fs::create_dir_all(&base)?;

  let state_path = paths::killswitch_state_path(&base);
  let mut state = load_state_or_default(&state_path);

  let backend = firewall::enable_rules()?;

  if state.keep_locked {
    tracing::info!(
      incident_id = %incident_id,
      group = FIREWALL_RULE_GROUP,
      "auto-enable: resetting keep_locked=false so failsafe can restore by default"
    );
  }
  state.keep_locked = false;

  let enabled_at = now_unix_ms();
  let deadline = enabled_at.saturating_add(failsafe_minutes.saturating_mul(60_000));

  state.enabled = true;
  state.enabled_mode = Some(KillSwitchMode::AutoRedOnly);
  state.enabled_at_unix_ms = Some(enabled_at);
  state.failsafe_deadline_unix_ms = Some(deadline);
  state.last_incident_id = Some(incident_id.to_string());
  save_state(&state_path, &state)?;

  tracing::warn!(
    incident_id = %incident_id,
    group = FIREWALL_RULE_GROUP,
    backend = ?backend,
    reason = "auto_red",
    failsafe_minutes,
    failsafe_deadline_unix_ms = deadline,
    timestamp_unix_ms = enabled_at,
    "kill switch enabled"
  );

  Ok(())
}

pub fn disable() -> anyhow::Result<()> {
  disable_with_reason("manual_restore", None)
}

pub fn disable_with_reason(reason: &str, incident_id: Option<&str>) -> anyhow::Result<()> {
  if runtime::is_dry_run() {
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      reason,
      incident_id = incident_id.unwrap_or(""),
      "DRY-RUN: would remove firewall rules (group AI_DEFENDER_KILLSWITCH)"
    );
    return Ok(());
  }

  let base = paths::base_dir()?;
  let state_path = paths::killswitch_state_path(&base);

  let backend = firewall::disable_rules()?;

  let mut state = load_state_or_default(&state_path);
  state.enabled = false;
  state.enabled_mode = None;
  state.enabled_at_unix_ms = None;
  state.failsafe_deadline_unix_ms = None;
  state.last_incident_id = None;
  save_state(&state_path, &state)?;

  tracing::info!(
    group = FIREWALL_RULE_GROUP,
    backend = ?backend,
    reason,
    incident_id = incident_id.unwrap_or(""),
    timestamp_unix_ms = now_unix_ms(),
    "kill switch disabled"
  );
  Ok(())
}

fn should_auto_restore(state: &KillSwitchState) -> bool {
  if !state.enabled {
    return false;
  }
  if state.keep_locked {
    return false;
  }
  if state.enabled_mode != Some(KillSwitchMode::AutoRedOnly) {
    return false;
  }
  let deadline = match state.failsafe_deadline_unix_ms {
    Some(d) => d,
    None => return false,
  };
  now_unix_ms() >= deadline
}

fn load_state(path: &Path) -> anyhow::Result<KillSwitchState> {
  if !path.exists() {
    return Ok(KillSwitchState::default());
  }
  let raw = fs::read_to_string(path)?;
  let state: KillSwitchState = toml::from_str(&raw)?;
  Ok(state)
}

fn load_state_or_default(path: &Path) -> KillSwitchState {
  match load_state(path) {
    Ok(s) => s,
    Err(e) => {
      tracing::error!(error = ?e, "failed to load kill switch state; using defaults");
      KillSwitchState::default()
    }
  }
}

fn save_state(path: &Path, state: &KillSwitchState) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("state path has no parent: {}", path.display()))?;
  fs::create_dir_all(parent)?;

  let raw = toml::to_string_pretty(state)?;
  write_atomic(path, &raw)?;
  Ok(())
}

fn write_atomic(path: &Path, contents: &str) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("file path has no parent: {}", path.display()))?;
  let tmp = parent.join(format!(
    ".{}.tmp",
    path.file_name().unwrap_or_default().to_string_lossy()
  ));
  fs::write(&tmp, contents)?;
  fs::rename(&tmp, path)?;
  Ok(())
}

fn now_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or(Duration::from_secs(0))
    .as_millis() as u64
}

pub fn state_file_path_for_docs() -> anyhow::Result<PathBuf> {
  let base = paths::base_dir()?;
  Ok(paths::killswitch_state_path(&base))
}

pub fn poll_failsafe() -> anyhow::Result<()> {
  let base = paths::base_dir()?;
  let state_path = paths::killswitch_state_path(&base);
  let state = load_state_or_default(&state_path);

  if should_auto_restore(&state) {
    let incident_id = state.last_incident_id.clone();
    tracing::warn!(
      group = FIREWALL_RULE_GROUP,
      incident_id = incident_id.as_deref().unwrap_or(""),
      timestamp_unix_ms = now_unix_ms(),
      reason = "failsafe_expired",
      "failsafe expired; restoring network"
    );
    disable_with_reason("failsafe_expired", incident_id.as_deref())?;
  }

  Ok(())
}
