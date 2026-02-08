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
