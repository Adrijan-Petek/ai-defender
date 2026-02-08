use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static FILE_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

pub fn init_file_only(log_dir: &Path, level: &str, retention_days: u64) -> anyhow::Result<()> {
  init_impl(log_dir, level, retention_days, false)
}

pub fn init_file_and_stderr(
  log_dir: &Path,
  level: &str,
  retention_days: u64,
) -> anyhow::Result<()> {
  init_impl(log_dir, level, retention_days, true)
}

fn init_impl(
  log_dir: &Path,
  level: &str,
  retention_days: u64,
  stderr: bool,
) -> anyhow::Result<()> {
  fs::create_dir_all(log_dir)?;
  cleanup_old_logs(log_dir, retention_days)?;

  let file_appender = tracing_appender::rolling::daily(log_dir, "agent-core.log");
  let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
  let _ = FILE_GUARD.set(guard);

  let filter = tracing_subscriber::EnvFilter::try_new(level)
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

  let file_layer = tracing_subscriber::fmt::layer()
    .with_ansi(false)
    .with_writer(file_writer)
    .with_target(true);

  if stderr {
    let stderr_layer = tracing_subscriber::fmt::layer()
      .with_ansi(false)
      .with_writer(std::io::stderr)
      .with_target(true);

    tracing_subscriber::registry()
      .with(filter)
      .with(file_layer)
      .with(stderr_layer)
      .init();
  } else {
    tracing_subscriber::registry().with(filter).with(file_layer).init();
  }

  Ok(())
}

fn cleanup_old_logs(log_dir: &Path, retention_days: u64) -> anyhow::Result<()> {
  if retention_days == 0 {
    return Ok(());
  }

  let cutoff = SystemTime::now()
    .checked_sub(Duration::from_secs(retention_days.saturating_mul(24 * 60 * 60)))
    .unwrap_or(SystemTime::UNIX_EPOCH);

  let entries = match fs::read_dir(log_dir) {
    Ok(e) => e,
    Err(_) => return Ok(()),
  };

  for entry in entries.flatten() {
    let path: PathBuf = entry.path();
    if !is_agent_log_file(&path) {
      continue;
    }

    let md = match entry.metadata() {
      Ok(m) => m,
      Err(_) => continue,
    };

    let modified = match md.modified() {
      Ok(t) => t,
      Err(_) => continue,
    };

    if modified < cutoff {
      let _ = fs::remove_file(&path);
    }
  }

  Ok(())
}

fn is_agent_log_file(path: &Path) -> bool {
  let name = match path.file_name().and_then(|n| n.to_str()) {
    Some(n) => n,
    None => return false,
  };

  name == "agent-core.log" || name.starts_with("agent-core.log.")
}

