use crate::config::Config;
use crate::license::{self, LicenseState};
use crate::paths;
use crate::types::now_unix_ms;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

pub mod fetch;
pub mod schema;
pub mod verify;

use schema::{ReputationLists, ThreatFeedBundle};

pub struct DownloadedBundle {
  pub bundle_json: Vec<u8>,
  pub signature: Vec<u8>,
}

pub trait ThreatFeedClient {
  fn fetch_latest(&self) -> anyhow::Result<DownloadedBundle>;
}

pub struct DisabledClient;

impl ThreatFeedClient for DisabledClient {
  fn fetch_latest(&self) -> anyhow::Result<DownloadedBundle> {
    anyhow::bail!("threat feed download is disabled by default; use offline import")
  }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BundleMeta {
  pub last_imported_at: Option<u64>,
  pub last_verified_at: Option<u64>,
  pub last_refresh_attempt_at: Option<u64>,
  pub last_refresh_result: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BundleStatus {
  pub present: bool,
  pub rules_version: Option<u64>,
  pub created_at: Option<u64>,
  pub verified_at: Option<u64>,
  pub last_refresh_attempt_at: Option<u64>,
  pub last_refresh_result: Option<String>,
}

impl BundleStatus {
  pub fn none() -> Self {
    Self {
      present: false,
      rules_version: None,
      created_at: None,
      verified_at: None,
      last_refresh_attempt_at: None,
      last_refresh_result: None,
    }
  }
}

#[derive(Debug, Clone)]
pub struct FeedStatus {
  pub installed: bool,
  pub verified: bool,
  pub version: Option<u64>,
  pub installed_at_unix_ms: Option<u64>,
  pub checked_at_unix_ms: u64,
  pub reason: Option<String>,
}

impl FeedStatus {
  pub fn none(reason: Option<String>) -> Self {
    Self {
      installed: false,
      verified: false,
      version: None,
      installed_at_unix_ms: None,
      checked_at_unix_ms: now_unix_ms(),
      reason,
    }
  }
}

#[derive(Debug, Clone)]
pub struct AutoRefreshEligibility {
  pub eligible: bool,
  pub interval_minutes: u64,
  pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AutoRefreshStatus {
  pub enabled: bool,
  pub interval_minutes: u64,
  pub eligible: bool,
  pub reason: String,
  pub last_attempt_at: Option<u64>,
  pub last_result: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshNowResult {
  pub attempted: bool,
  pub success: bool,
  pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct AutoRefreshScheduler {
  next_due_unix_ms: Option<u64>,
}

impl AutoRefreshScheduler {
  pub fn new(cfg: &Config, base: &Path) -> Self {
    let mut out = Self::default();
    out.recompute_due(cfg, base);
    out
  }

  pub fn tick(&mut self, cfg: &Config, base: &Path) {
    let eligibility = auto_refresh_eligibility(cfg, base);
    if !eligibility.eligible {
      self.next_due_unix_ms = None;
      return;
    }

    let now = now_unix_ms();
    let interval_ms = eligibility.interval_minutes.saturating_mul(60_000);

    if self.next_due_unix_ms.is_none() {
      self.next_due_unix_ms = Some(now.saturating_add(interval_ms));
      return;
    }

    let Some(next_due) = self.next_due_unix_ms else {
      return;
    };
    if now < next_due {
      return;
    }

    let result = refresh_now(cfg, base);
    if result.attempted && result.success {
      tracing::info!("threat feed auto-refresh succeeded");
    } else if result.attempted {
      tracing::warn!(reason = %result.reason, "threat feed auto-refresh failed");
    }

    self.next_due_unix_ms = Some(now.saturating_add(interval_ms));
  }

  fn recompute_due(&mut self, cfg: &Config, base: &Path) {
    let eligibility = auto_refresh_eligibility(cfg, base);
    if !eligibility.eligible {
      self.next_due_unix_ms = None;
      return;
    }
    let now = now_unix_ms();
    self.next_due_unix_ms = Some(now.saturating_add(eligibility.interval_minutes.saturating_mul(60_000)));
  }
}

pub fn verify_bundle_signature(bundle_json: &[u8], sig_bytes: &[u8]) -> bool {
  verify::verify_bundle_signature(bundle_json, sig_bytes).is_ok()
}

pub fn verify_files(bundle_path: &Path, sig_path: &Path) -> anyhow::Result<ThreatFeedBundle> {
  let bundle_json = fs::read(bundle_path).with_context(|| format!("read {}", bundle_path.display()))?;
  let sig_raw = fs::read(sig_path).with_context(|| format!("read {}", sig_path.display()))?;
  verify_bundle_bytes(&bundle_json, &sig_raw)
}

pub fn load_current() -> Option<ThreatFeedBundle> {
  let base = paths::base_dir().ok()?;
  load_current_at(&base)
}

pub fn load_current_at(base: &Path) -> Option<ThreatFeedBundle> {
  let bundle_path = paths::threat_feed_bundle_path(base);
  let sig_path = paths::threat_feed_sig_path(base);

  if let Ok(bundle) = verify_files(&bundle_path, &sig_path) {
    let _ = mark_verified(base);
    return Some(bundle);
  }

  verify_last_good(base).ok()
}

pub fn get_reputation_lists() -> ReputationLists {
  load_current()
    .map(|bundle| bundle.reputation)
    .unwrap_or_default()
}

pub fn get_reputation_lists_at(base: &Path) -> ReputationLists {
  load_current_at(base)
    .map(|bundle| bundle.reputation)
    .unwrap_or_default()
}

pub fn bundle_status() -> BundleStatus {
  let Ok(base) = paths::base_dir() else {
    return BundleStatus::none();
  };
  bundle_status_at(&base)
}

pub fn bundle_status_at(base: &Path) -> BundleStatus {
  let meta = read_meta(base);

  if let Some(bundle) = load_current_at(base) {
    return BundleStatus {
      present: true,
      rules_version: Some(bundle.rules_version),
      created_at: Some(bundle.created_at),
      verified_at: meta.last_verified_at,
      last_refresh_attempt_at: meta.last_refresh_attempt_at,
      last_refresh_result: meta.last_refresh_result,
    };
  }

  BundleStatus {
    present: false,
    rules_version: None,
    created_at: None,
    verified_at: meta.last_verified_at,
    last_refresh_attempt_at: meta.last_refresh_attempt_at,
    last_refresh_result: meta.last_refresh_result,
  }
}

pub fn import(base: &Path, src_bundle: &Path, src_sig: &Path) -> anyhow::Result<BundleStatus> {
  let bundle_json = fs::read(src_bundle).with_context(|| format!("read {}", src_bundle.display()))?;
  let sig_raw = fs::read(src_sig).with_context(|| format!("read {}", src_sig.display()))?;

  verify_bundle_bytes(&bundle_json, &sig_raw)?;
  install_verified_bundle(base, &bundle_json, &sig_raw)?;
  Ok(bundle_status_at(base))
}

pub fn refresh_now(cfg: &Config, base: &Path) -> RefreshNowResult {
  let eligibility = auto_refresh_eligibility(cfg, base);
  if !eligibility.eligible {
    return RefreshNowResult {
      attempted: false,
      success: false,
      reason: eligibility.reason,
    };
  }

  let attempt_at = now_unix_s();
  let mut meta = read_meta(base);
  meta.last_refresh_attempt_at = Some(attempt_at);

  let fetched = match fetch::fetch_bundle(&cfg.threat_feed) {
    Ok(v) => v,
    Err(e) => {
      meta.last_refresh_result = Some(format!("failed: {}", short_error(&e)));
      let _ = write_meta(base, &meta);
      return RefreshNowResult {
        attempted: true,
        success: false,
        reason: format!("refresh failed: {}", short_error(&e)),
      };
    }
  };

  if let Err(e) = verify_bundle_bytes(&fetched.bundle_json, &fetched.bundle_sig) {
      meta.last_refresh_result = Some(format!("failed: verification {}", short_error(&e)));
      let _ = write_meta(base, &meta);
      tracing::warn!(host = %fetched.host, reason = %short_error(&e), "threat feed verification failed");
      return RefreshNowResult {
        attempted: true,
        success: false,
        reason: format!("verification failed: {}", short_error(&e)),
      };
    };
  }

  if let Err(e) = install_verified_bundle(base, &fetched.bundle_json, &fetched.bundle_sig) {
    meta.last_refresh_result = Some(format!("failed: install {}", short_error(&e)));
    let _ = write_meta(base, &meta);
    return RefreshNowResult {
      attempted: true,
      success: false,
      reason: format!("install failed: {}", short_error(&e)),
    };
  }

  let mut meta2 = read_meta(base);
  meta2.last_refresh_attempt_at = Some(attempt_at);
  meta2.last_refresh_result = Some("success".to_string());
  let _ = write_meta(base, &meta2);

  tracing::info!(host = %fetched.host, "threat feed refresh succeeded");
  RefreshNowResult {
    attempted: true,
    success: true,
    reason: "success".to_string(),
  }
}

pub fn auto_refresh_eligibility(cfg: &Config, base: &Path) -> AutoRefreshEligibility {
  if !cfg.threat_feed.auto_refresh {
    return AutoRefreshEligibility {
      eligible: false,
      interval_minutes: cfg.threat_feed.refresh_interval_minutes,
      reason: "Auto refresh disabled (config)".to_string(),
    };
  }

  let lic = license::status(base);
  match lic.state {
    LicenseState::ProActive => {}
    LicenseState::Community => {
      return AutoRefreshEligibility {
        eligible: false,
        interval_minutes: cfg.threat_feed.refresh_interval_minutes,
        reason: "Auto refresh disabled (Community mode)".to_string(),
      };
    }
    _ => {
      return AutoRefreshEligibility {
        eligible: false,
        interval_minutes: cfg.threat_feed.refresh_interval_minutes,
        reason: "Auto refresh disabled (license not active)".to_string(),
      };
    }
  }

  if let Err(e) = fetch::validate_refresh_config(&cfg.threat_feed) {
    return AutoRefreshEligibility {
      eligible: false,
      interval_minutes: cfg.threat_feed.refresh_interval_minutes,
      reason: format!("Auto refresh disabled (invalid config: {})", short_error(&e)),
    };
  }

  AutoRefreshEligibility {
    eligible: true,
    interval_minutes: cfg.threat_feed.refresh_interval_minutes,
    reason: "eligible".to_string(),
  }
}

pub fn auto_refresh_status(cfg: &Config, base: &Path) -> AutoRefreshStatus {
  let eligibility = auto_refresh_eligibility(cfg, base);
  let meta = read_meta(base);
  AutoRefreshStatus {
    enabled: cfg.threat_feed.auto_refresh,
    interval_minutes: cfg.threat_feed.refresh_interval_minutes,
    eligible: eligibility.eligible,
    reason: eligibility.reason,
    last_attempt_at: meta.last_refresh_attempt_at,
    last_result: meta.last_refresh_result,
  }
}

pub fn status(base: &Path) -> FeedStatus {
  let checked = now_unix_ms();
  let st = bundle_status_at(base);

  if !st.present {
    let out = FeedStatus::none(Some("no valid bundle installed".to_string()));
    let _ = write_state(base, &out);
    return out;
  }

  let out = FeedStatus {
    installed: true,
    verified: true,
    version: st.rules_version,
    installed_at_unix_ms: st.created_at.map(|seconds| seconds.saturating_mul(1000)),
    checked_at_unix_ms: checked,
    reason: st.last_refresh_result.clone(),
  };
  let _ = write_state(base, &out);
  out
}

fn install_verified_bundle(
  base: &Path,
  bundle_json: &[u8],
  sig_raw: &[u8],
) -> anyhow::Result<()> {
  let feed_dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&feed_dir).with_context(|| format!("create {}", feed_dir.display()))?;

  let dst_bundle = paths::threat_feed_bundle_path(base);
  let dst_sig = paths::threat_feed_sig_path(base);

  atomic_write_file(&dst_bundle, bundle_json)?;
  atomic_write_file(&dst_sig, sig_raw)?;
  write_last_good(base, bundle_json, sig_raw)?;

  let now = now_unix_s();
  let mut meta = read_meta(base);
  meta.last_imported_at = Some(now);
  meta.last_verified_at = Some(now);
  write_meta(base, &meta)?;
  Ok(())
}

fn verify_bundle_bytes(bundle_json: &[u8], sig_raw: &[u8]) -> anyhow::Result<ThreatFeedBundle> {
  let sig = decode_sig_file(sig_raw)?;
  verify::verify_bundle_signature(bundle_json, &sig)?;
  let bundle: ThreatFeedBundle = serde_json::from_slice(bundle_json).context("parse bundle JSON")?;
  validate_bundle_schema(&bundle)?;
  Ok(bundle)
}

fn validate_bundle_schema(bundle: &ThreatFeedBundle) -> anyhow::Result<()> {
  if bundle.version != 1 {
    anyhow::bail!("unsupported bundle version {}; expected 1", bundle.version);
  }
  if uuid::Uuid::parse_str(bundle.bundle_id.trim()).is_err() {
    anyhow::bail!("bundle_id must be a UUID");
  }
  if bundle.created_at == 0 {
    anyhow::bail!("created_at must be > 0");
  }
  if bundle.rules_version == 0 {
    anyhow::bail!("rules_version must be > 0");
  }

  for rule in &bundle.rules {
    if rule.rule_id.trim().is_empty() {
      anyhow::bail!("rule_id must not be empty");
    }
  }

  Ok(())
}

fn decode_sig_file(sig_raw: &[u8]) -> anyhow::Result<Vec<u8>> {
  if sig_raw.len() == 64 {
    return Ok(sig_raw.to_vec());
  }
  let text = std::str::from_utf8(sig_raw).context("signature file must be raw bytes or UTF-8")?;
  verify::decode_sig_base64url(text)
}

fn read_meta(base: &Path) -> BundleMeta {
  let path = paths::threat_feed_meta_path(base);
  let Ok(bytes) = fs::read(&path) else {
    return BundleMeta::default();
  };
  serde_json::from_slice::<BundleMeta>(&bytes).unwrap_or_default()
}

fn write_meta(base: &Path, meta: &BundleMeta) -> anyhow::Result<()> {
  let dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
  let bytes = serde_json::to_vec_pretty(meta)?;
  atomic_write_file(&paths::threat_feed_meta_path(base), &bytes)
}

fn mark_verified(base: &Path) -> anyhow::Result<()> {
  let now = now_unix_s();
  let mut meta = read_meta(base);
  meta.last_verified_at = Some(now);
  write_meta(base, &meta)
}

fn last_good_bundle_path(base: &Path) -> PathBuf {
  paths::threat_feed_dir(base).join("bundle.json.last-good")
}

fn last_good_sig_path(base: &Path) -> PathBuf {
  paths::threat_feed_dir(base).join("bundle.sig.last-good")
}

fn write_last_good(base: &Path, bundle_json: &[u8], sig_raw: &[u8]) -> anyhow::Result<()> {
  let dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
  atomic_write_file(&last_good_bundle_path(base), bundle_json)?;
  atomic_write_file(&last_good_sig_path(base), sig_raw)?;
  Ok(())
}

fn verify_last_good(base: &Path) -> anyhow::Result<ThreatFeedBundle> {
  let b = last_good_bundle_path(base);
  let s = last_good_sig_path(base);
  verify_files(&b, &s)
}

fn atomic_write_file(dst: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  let dir = dst
    .parent()
    .ok_or_else(|| anyhow::anyhow!("destination has no parent directory"))?;
  fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

  let tmp = tmp_path(dst);
  fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
  fs::rename(&tmp, dst).with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))?;
  Ok(())
}

fn tmp_path(dst: &Path) -> PathBuf {
  let name = dst.file_name().and_then(|s| s.to_str()).unwrap_or("tmp");
  dst.with_file_name(format!(".{name}.tmp"))
}

fn write_state(base: &Path, st: &FeedStatus) -> anyhow::Result<()> {
  let dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
  let path = paths::threat_feed_state_path(base);
  let bundle = bundle_status_at(base);

  let content = format!(
    "installed = {}\nverified = {}\nversion = {}\ninstalled_at_unix_ms = {}\nchecked_at_unix_ms = {}\nreason = {}\ncreated_at_unix_seconds = {}\nlast_verified_at_unix_seconds = {}\nlast_refresh_attempt_at_unix_seconds = {}\nlast_refresh_result = {}\n",
    st.installed,
    st.verified,
    toml_u64_or_null(st.version),
    toml_u64_or_null(st.installed_at_unix_ms),
    st.checked_at_unix_ms,
    toml_string_or_null(st.reason.as_deref()),
    toml_u64_or_null(bundle.created_at),
    toml_u64_or_null(bundle.verified_at),
    toml_u64_or_null(bundle.last_refresh_attempt_at),
    toml_string_or_null(bundle.last_refresh_result.as_deref()),
  );

  atomic_write_file(&path, content.as_bytes())
}

fn toml_string_or_null(v: Option<&str>) -> String {
  match v {
    Some(s) => format!("\"{}\"", s.replace('"', "\\\"")),
    None => "null".to_string(),
  }
}

fn toml_u64_or_null(v: Option<u64>) -> String {
  match v {
    Some(x) => x.to_string(),
    None => "null".to_string(),
  }
}

fn short_error(e: &anyhow::Error) -> String {
  let text = e.to_string();
  let count = text.chars().count();
  if count <= 180 {
    return text;
  }
  let prefix: String = text.chars().take(180).collect();
  format!("{prefix}...")
}

fn now_unix_s() -> u64 {
  now_unix_ms() / 1000
}
