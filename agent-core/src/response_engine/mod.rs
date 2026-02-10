use crate::config::Config;
use crate::incident_store;
use crate::kill_switch;
use crate::types::{Incident, Severity};

pub fn handle_incident(cfg: &Config, incident: &mut Incident) -> anyhow::Result<()> {
  let incident_id = incident.incident_id.clone();
  let sev = incident.max_severity();
  incident.severity = sev;

  tracing::info!(
    incident_id = %incident_id,
    severity = ?sev,
    findings = incident.findings.len(),
    "incident created"
  );

  for f in &incident.findings {
    tracing::info!(
      incident_id = %incident_id,
      rule_id = %f.rule_id,
      severity = ?f.severity,
      "finding: {}",
      f.description
    );
  }

  if sev == Severity::Red {
    if let Err(e) = on_red_incident(cfg, incident) {
      tracing::error!(
        incident_id = %incident_id,
        error = ?e,
        "RED incident response failed (continuing)"
      );
      incident
        .actions_taken
        .push("red_response_failed".to_string());
    }
  } else {
    tracing::info!(
      incident_id = %incident_id,
      severity = ?sev,
      "no automatic response for non-RED incident"
    );
  }

  match incident_store::store_incident(incident) {
    Ok(path) => tracing::info!(
      incident_id = %incident_id,
      incident_path = %path.display(),
      "incident stored"
    ),
    Err(e) => tracing::error!(
      incident_id = %incident_id,
      error = ?e,
      "failed to store incident (continuing)"
    ),
  }

  Ok(())
}

pub fn on_red_incident(cfg: &Config, incident: &mut Incident) -> anyhow::Result<()> {
  let incident_id = incident.incident_id.clone();

  // Placeholder: in v1 MVP we may not have a PID yet.
  tracing::warn!(
    incident_id = %incident_id,
    "RED incident response: process termination not implemented (no PID)"
  );
  incident
    .actions_taken
    .push("process_kill_skipped_no_pid".to_string());

  tracing::warn!(
    incident_id = %incident_id,
    "RED incident response: quarantine not implemented (no executable path)"
  );
  incident
    .actions_taken
    .push("quarantine_skipped_no_path".to_string());

  if !cfg.killswitch.enabled {
    tracing::info!(
      incident_id = %incident_id,
      "kill switch is disabled by config; skipping"
    );
    return Ok(());
  }

  if cfg.mode == crate::config::Mode::Learning {
    tracing::info!(
      incident_id = %incident_id,
      "learning mode: not auto-triggering kill switch"
    );
    incident
      .actions_taken
      .push("killswitch_skipped_learning_mode".to_string());
    return Ok(());
  }

  if cfg.killswitch.auto_trigger {
    tracing::warn!(
      incident_id = %incident_id,
      "auto-triggering network kill switch (RED only)"
    );

    match kill_switch::enable_auto(&incident_id, cfg.killswitch.failsafe_minutes) {
      Ok(()) => {
        incident
          .actions_taken
          .push("killswitch_enable_auto".to_string());
        incident
          .actions_taken
          .push("killswitch_failsafe_deadline_set".to_string());
      }
      Err(e) => {
        tracing::error!(
          incident_id = %incident_id,
          error = ?e,
          "auto-trigger kill switch failed"
        );
        incident
          .actions_taken
          .push("killswitch_enable_auto_failed".to_string());
      }
    }
  } else {
    tracing::info!(
      incident_id = %incident_id,
      "auto-trigger disabled by config; skipping kill switch"
    );
    incident
      .actions_taken
      .push("killswitch_skipped_auto_trigger_disabled".to_string());
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{KillSwitchConfig, Mode};
  use crate::types::{Finding, Severity};

  #[test]
  fn learning_mode_skips_killswitch_auto_response() {
    let cfg = Config {
      mode: Mode::Learning,
      killswitch: KillSwitchConfig {
        enabled: true,
        auto_trigger: true,
        failsafe_minutes: 10,
      },
      ..Config::default()
    };

    let mut inc = Incident::new(vec![Finding {
      rule_id: "R009".to_string(),
      severity: Severity::Red,
      description: "test".to_string(),
      evidence: vec![],
      timestamp_unix_ms: 1_700_000_000_000,
    }]);

    on_red_incident(&cfg, &mut inc).unwrap();

    assert!(inc
      .actions_taken
      .iter()
      .any(|a| a == "killswitch_skipped_learning_mode"));
    assert!(!inc
      .actions_taken
      .iter()
      .any(|a| a == "killswitch_enable_auto"));
  }
}
