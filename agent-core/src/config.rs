use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
  pub mode: Mode,
  pub correlation_window_seconds: u64,
  pub logging: LoggingConfig,
  pub killswitch: KillSwitchConfig,
  pub allowlist: AllowlistConfig,
  pub protected: ProtectedConfig,
  pub threat_feed: ThreatFeedConfig,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      mode: Mode::Learning,
      correlation_window_seconds: default_correlation_window_seconds(),
      logging: LoggingConfig::default(),
      killswitch: KillSwitchConfig::default(),
      allowlist: AllowlistConfig::default(),
      protected: ProtectedConfig::default(),
      threat_feed: ThreatFeedConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
  Learning,
  Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,

  #[serde(default = "default_retention_days")]
  pub retention_days: u64,
}

fn default_log_level() -> String {
  "info".to_string()
}

fn default_retention_days() -> u64 {
  14
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
      retention_days: default_retention_days(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,

  #[serde(default = "default_true")]
  pub auto_trigger: bool,

  #[serde(default = "default_failsafe_minutes")]
  pub failsafe_minutes: u64,
}

impl Default for KillSwitchConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      auto_trigger: true,
      failsafe_minutes: default_failsafe_minutes(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
  #[serde(default = "default_allowlist_publishers")]
  pub publishers: Vec<String>,

  #[serde(default)]
  pub paths_allowlist: Vec<String>,
}

impl Default for AllowlistConfig {
  fn default() -> Self {
    Self {
      publishers: default_allowlist_publishers(),
      paths_allowlist: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedConfig {
  #[serde(default = "default_chrome_targets")]
  pub chrome_targets: Vec<String>,

  #[serde(default = "default_firefox_targets")]
  pub firefox_targets: Vec<String>,
}

impl Default for ProtectedConfig {
  fn default() -> Self {
    Self {
      chrome_targets: default_chrome_targets(),
      firefox_targets: default_firefox_targets(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
  #[serde(default)]
  pub auto_refresh: bool,

  #[serde(default = "default_refresh_interval_minutes")]
  pub refresh_interval_minutes: u64,

  #[serde(default = "default_threat_feed_endpoints")]
  pub endpoints: Vec<String>,

  #[serde(default = "default_threat_feed_allowlist_domains")]
  pub allowlist_domains: Vec<String>,

  #[serde(default = "default_threat_feed_timeout_seconds")]
  pub timeout_seconds: u64,
}

impl Default for ThreatFeedConfig {
  fn default() -> Self {
    Self {
      auto_refresh: false,
      refresh_interval_minutes: default_refresh_interval_minutes(),
      endpoints: default_threat_feed_endpoints(),
      allowlist_domains: default_threat_feed_allowlist_domains(),
      timeout_seconds: default_threat_feed_timeout_seconds(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacySafetyConfig {
  #[serde(default)]
  pub strict_mode: bool,
}

fn default_true() -> bool {
  true
}

fn default_failsafe_minutes() -> u64 {
  10
}

fn default_correlation_window_seconds() -> u64 {
  120
}

fn default_refresh_interval_minutes() -> u64 {
  60
}

fn default_threat_feed_endpoints() -> Vec<String> {
  vec!["https://updates.aidefender.shop/feed/".to_string()]
}

fn default_threat_feed_allowlist_domains() -> Vec<String> {
  vec!["updates.aidefender.shop".to_string()]
}

fn default_threat_feed_timeout_seconds() -> u64 {
  10
}

fn default_allowlist_publishers() -> Vec<String> {
  vec![
    "Microsoft Windows".to_string(),
    "Google LLC".to_string(),
    "Mozilla Corporation".to_string(),
  ]
}

fn default_chrome_targets() -> Vec<String> {
  vec![
    "Login Data".to_string(),
    "Cookies".to_string(),
    "Local State".to_string(),
  ]
}

fn default_firefox_targets() -> Vec<String> {
  vec![
    "logins.json".to_string(),
    "key4.db".to_string(),
    "cookies.sqlite".to_string(),
  ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigFile {
  #[serde(default)]
  pub mode: Option<Mode>,

  #[serde(default)]
  pub correlation_window_seconds: Option<u64>,

  #[serde(default)]
  pub logging: Option<LoggingConfig>,

  #[serde(default)]
  pub killswitch: Option<KillSwitchConfig>,

  #[serde(default)]
  pub allowlist: Option<AllowlistConfig>,

  #[serde(default)]
  pub protected: Option<ProtectedConfig>,

  #[serde(default)]
  pub threat_feed: Option<ThreatFeedConfig>,

  // Back-compat: old configs had `[safety] strict_mode = true|false`.
  #[serde(default)]
  pub safety: Option<LegacySafetyConfig>,

  // Back-compat: old configs had top-level `failsafe_minutes`.
  #[serde(default)]
  pub failsafe_minutes: Option<u64>,
}

impl ConfigFile {
  fn normalize(self) -> Config {
    let mut cfg = Config::default();
    if let Some(mode) = self.mode {
      cfg.mode = mode;
    } else if self.safety.as_ref().map(|s| s.strict_mode).unwrap_or(false) {
      cfg.mode = Mode::Strict;
    }

    if let Some(w) = self.correlation_window_seconds {
      cfg.correlation_window_seconds = w;
    }
    if let Some(l) = self.logging {
      cfg.logging = l;
    }
    let killswitch_opt = self.killswitch;
    if let Some(k) = killswitch_opt.clone() {
      cfg.killswitch = k;
    }
    if let Some(legacy) = self.failsafe_minutes {
      let can_apply = killswitch_opt
        .as_ref()
        .map(|ks| ks.failsafe_minutes == default_failsafe_minutes())
        .unwrap_or(true);
      if can_apply {
        cfg.killswitch.failsafe_minutes = legacy;
      }
    }
    if let Some(a) = self.allowlist {
      cfg.allowlist = a;
    }
    if let Some(p) = self.protected {
      cfg.protected = p;
    }
    if let Some(tf) = self.threat_feed {
      cfg.threat_feed = tf;
    }

    if let Some(reason) = validate_threat_feed_config(&cfg.threat_feed) {
      cfg.threat_feed.auto_refresh = false;
      tracing::warn!(
        reason = %reason,
        "threat_feed config invalid; auto refresh disabled"
      );
    }

    cfg
  }

  fn needs_upgrade(&self) -> bool {
    self.mode.is_none()
      || self.correlation_window_seconds.is_none()
      || self.logging.is_none()
      || self.killswitch.is_none()
      || self.allowlist.is_none()
      || self.protected.is_none()
      || self.threat_feed.is_none()
  }
}

pub fn load_or_create_default(path: &Path) -> anyhow::Result<Config> {
  load_impl(path, true)
}

pub fn load_or_default_readonly(path: &Path) -> anyhow::Result<Config> {
  load_impl(path, false)
}

fn load_impl(path: &Path, allow_writes: bool) -> anyhow::Result<Config> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("config path has no parent: {}", path.display()))?;
  if allow_writes {
    fs::create_dir_all(parent)?;
  }

  if !path.exists() {
    let cfg = Config::default();
    if allow_writes {
      write_atomic(path, &toml::to_string_pretty(&to_config_file(&cfg))?)?;
    } else {
      eprintln!(
        "AI Defender: config missing at {}; using defaults in read-only mode (--dry-run).",
        path.display()
      );
    }
    return Ok(cfg);
  }

  let raw = fs::read_to_string(path)?;
  match toml::from_str::<ConfigFile>(&raw) {
    Ok(file) => {
      let cfg = file.clone().normalize();
      if allow_writes && file.needs_upgrade() {
        let ts = std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap_or_default()
          .as_secs();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let backup = parent.join(format!("config.toml.bak-{ts}"));
        let _ = fs::copy(path, &backup);
        let _ = write_atomic(path, &toml::to_string_pretty(&to_config_file(&cfg))?);
        eprintln!(
          "AI Defender: upgraded config defaults written to {} (backup: {})",
          path.display(),
          backup.display()
        );
      } else if !allow_writes && file.needs_upgrade() {
        eprintln!(
          "AI Defender: config at {} needs upgrade; proceeding without writing in --dry-run mode.",
          path.display()
        );
      }
      Ok(cfg)
    }
    Err(e) => {
      let cfg = Config::default();
      if allow_writes {
        let ts = std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap_or_default()
          .as_secs();
        let backup = parent.join(format!("config.toml.bad-{ts}"));
        let _ = fs::rename(path, &backup);
        write_atomic(path, &toml::to_string_pretty(&to_config_file(&cfg))?)?;
        eprintln!(
          "AI Defender: invalid config at {} (backed up to {}): {e}",
          path.display(),
          backup.display()
        );
      } else {
        eprintln!(
          "AI Defender: invalid config at {}; using defaults in read-only mode (--dry-run): {e}",
          path.display()
        );
      }
      Ok(cfg)
    }
  }
}

fn to_config_file(cfg: &Config) -> ConfigFile {
  ConfigFile {
    mode: Some(cfg.mode),
    correlation_window_seconds: Some(cfg.correlation_window_seconds),
    logging: Some(cfg.logging.clone()),
    killswitch: Some(cfg.killswitch.clone()),
    allowlist: Some(cfg.allowlist.clone()),
    protected: Some(cfg.protected.clone()),
    threat_feed: Some(cfg.threat_feed.clone()),
    safety: None,
    failsafe_minutes: None,
  }
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

fn validate_threat_feed_config(cfg: &ThreatFeedConfig) -> Option<String> {
  if cfg.refresh_interval_minutes == 0 {
    return Some("refresh_interval_minutes must be > 0".to_string());
  }
  if cfg.timeout_seconds == 0 {
    return Some("timeout_seconds must be > 0".to_string());
  }
  if cfg.endpoints.is_empty() {
    return Some("endpoints must not be empty".to_string());
  }
  if cfg.allowlist_domains.is_empty() {
    return Some("allowlist_domains must not be empty".to_string());
  }

  for endpoint in &cfg.endpoints {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
      return Some(format!("invalid endpoint URL: {endpoint}"));
    };
    if url.scheme() != "https" {
      return Some(format!("endpoint must use HTTPS: {endpoint}"));
    }
    let Some(host) = url.host_str() else {
      return Some(format!("endpoint has no host: {endpoint}"));
    };
    if !cfg.allowlist_domains.iter().any(|d| d == host) {
      return Some(format!("endpoint host not allowlisted: {host}"));
    }
  }

  None
}
