use crate::agent::Agent;
use crate::{config, kill_switch, logging, paths};
use std::sync::mpsc;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
  ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

pub const SERVICE_NAME: &str = "AI_DEFENDER_AGENT";

define_windows_service!(ffi_service_main, service_main);

pub fn run_service() -> anyhow::Result<()> {
  service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
  Ok(())
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
  if let Err(e) = run_service_inner() {
    // Logging may not be initialized yet; best-effort to Surface fatal issues.
    eprintln!("AI_DEFENDER_AGENT fatal error: {e:?}");
  }
}

fn run_service_inner() -> anyhow::Result<()> {
  let base = paths::base_dir()?;
  let config_path = paths::config_path(&base);
  let cfg = config::load_or_create_default(&config_path)?;

  logging::init_file_only(
    &paths::logs_dir(&base),
    &cfg.logging.level,
    cfg.logging.retention_days,
  )?;

  kill_switch::reconcile_on_startup(&cfg)?;

  let (stop_tx, stop_rx) = mpsc::channel::<()>();

  let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
    match control_event {
      ServiceControl::Stop | ServiceControl::Shutdown => {
        let _ = stop_tx.send(());
        ServiceControlHandlerResult::NoError
      }
      _ => ServiceControlHandlerResult::NotImplemented,
    }
  })?;

  set_service_status(&status_handle, ServiceState::StartPending, 1, Duration::from_secs(10))?;
  tracing::info!("service starting");
  set_service_status(&status_handle, ServiceState::Running, 0, Duration::default())?;

  let agent = Agent::new(cfg);
  let res = agent.run(stop_rx, Duration::from_millis(500));
  if let Err(e) = res {
    tracing::error!(error = ?e, "agent loop exited with error");
  }

  set_service_status(&status_handle, ServiceState::Stopped, 0, Duration::default())?;
  tracing::info!("service stopped");
  Ok(())
}

fn set_service_status(
  status_handle: &windows_service::service_control_handler::ServiceStatusHandle,
  state: ServiceState,
  checkpoint: u32,
  wait_hint: Duration,
) -> anyhow::Result<()> {
  let status = ServiceStatus {
    service_type: ServiceType::OWN_PROCESS,
    current_state: state,
    controls_accepted: match state {
      ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
      _ => ServiceControlAccept::empty(),
    },
    exit_code: ServiceExitCode::Win32(0),
    checkpoint,
    wait_hint,
    process_id: None,
  };
  status_handle.set_service_status(status)?;
  Ok(())
}
