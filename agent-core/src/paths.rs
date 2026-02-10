use std::path::{Path, PathBuf};

pub fn base_dir() -> anyhow::Result<PathBuf> {
  let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
  Ok(PathBuf::from(program_data).join("AI Defender"))
}

pub fn config_path(base: &Path) -> PathBuf {
  base.join("config.toml")
}

pub fn logs_dir(base: &Path) -> PathBuf {
  base.join("logs")
}

pub fn killswitch_state_path(base: &Path) -> PathBuf {
  base.join("killswitch-state.toml")
}

pub fn incidents_dir(base: &Path) -> PathBuf {
  base.join("incidents")
}

pub fn sysmon_bookmark_path(base: &Path) -> PathBuf {
  base.join("sysmon-bookmark.toml")
}

pub fn device_id_path(base: &Path) -> PathBuf {
  base.join("device_id.txt")
}

pub fn license_dir(base: &Path) -> PathBuf {
  base.join("license")
}

pub fn license_json_path(base: &Path) -> PathBuf {
  license_dir(base).join("license.json")
}

pub fn license_sig_path(base: &Path) -> PathBuf {
  license_dir(base).join("license.sig")
}

pub fn license_activation_path(base: &Path) -> PathBuf {
  license_dir(base).join("activation.json")
}

pub fn license_status_path(base: &Path) -> PathBuf {
  license_dir(base).join("status.toml")
}

pub fn threat_feed_dir(base: &Path) -> PathBuf {
  base.join("threat-feed")
}

pub fn threat_feed_bundle_path(base: &Path) -> PathBuf {
  threat_feed_dir(base).join("bundle.json")
}

pub fn threat_feed_sig_path(base: &Path) -> PathBuf {
  threat_feed_dir(base).join("bundle.sig")
}

pub fn threat_feed_state_path(base: &Path) -> PathBuf {
  threat_feed_dir(base).join("state.toml")
}
