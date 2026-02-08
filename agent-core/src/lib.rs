pub mod agent;
pub mod config;
pub mod console;
pub mod event_collector;
pub mod incident_store;
pub mod kill_switch;
pub mod logging;
pub mod paths;
pub mod response_engine;
pub mod rules_engine;
pub mod service;
pub mod types;

use std::sync::mpsc;
use std::time::Duration;

pub fn run_console(args: &[String]) -> anyhow::Result<()> {
  let base = paths::base_dir()?;
  let config_path = paths::config_path(&base);
  let cfg = config::load_or_create_default(&config_path)?;

  logging::init_file_and_stderr(
    &paths::logs_dir(&base),
    &cfg.logging.level,
    cfg.logging.retention_days,
  )?;

  kill_switch::reconcile_on_startup(&cfg)?;

  match console::run_console_command(&cfg, args)? {
    console::ConsoleAction::ExitOk => return Ok(()),
    console::ConsoleAction::RunAgent => {}
  }

  tracing::info!("starting AI Defender agent (console mode)");
  let (stop_tx, stop_rx) = mpsc::channel::<()>();

  let ctrlc_tx = stop_tx.clone();
  ctrlc::set_handler(move || {
    let _ = ctrlc_tx.send(());
  })?;

  agent::Agent::new(cfg).run(stop_rx, Duration::from_millis(500))?;
  tracing::info!("agent stopped");
  Ok(())
}
