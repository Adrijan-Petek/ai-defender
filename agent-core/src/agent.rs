use crate::config::Config;
use crate::event_collector;
use crate::kill_switch;
use crate::response_engine;
use crate::rules_engine;
use std::sync::mpsc;
use std::time::Duration;

pub struct Agent {
  cfg: Config,
}

impl Agent {
  pub fn new(cfg: Config) -> Self {
    Self { cfg }
  }

  pub fn run(&self, stop_rx: mpsc::Receiver<()>, tick: Duration) -> anyhow::Result<()> {
    let mut cfg = self.cfg.clone();
    if cfg.mode == crate::config::Mode::Strict && rules_engine::active_rule_ids().is_empty() {
      tracing::warn!(
        "strict mode requested but no active rules are loaded; refusing strict mode and staying in learning"
      );
      cfg.mode = crate::config::Mode::Learning;
    }

    tracing::info!(
      mode = ?cfg.mode,
      monitoring_only = (cfg.mode == crate::config::Mode::Learning),
      "agent main loop started"
    );

    let mut engine = rules_engine::Engine::new();

    loop {
      if stop_rx.recv_timeout(tick).is_ok() {
        break;
      }

      let _ = kill_switch::poll_failsafe();

      let events = event_collector::collect_once()?;
      if events.is_empty() {
        continue;
      }

      let incidents = engine.process(&cfg, &events)?;
      for mut incident in incidents {
        response_engine::handle_incident(&cfg, &mut incident)?;
      }
    }

    tracing::info!("agent main loop exiting");
    Ok(())
  }
}
