use crate::config::Config;
use crate::incident_store;
use crate::kill_switch;
use crate::types::{now_unix_ms, Event, FileAccessType};
use std::sync::mpsc;
use std::time::Duration;

pub enum ConsoleAction {
  RunAgent,
  ExitOk,
}

pub fn run_console_command(cfg: &Config, args: &[String]) -> anyhow::Result<ConsoleAction> {
  let args = strip_console_flag(args);

  if args.iter().any(|a| a == "--help" || a == "-h") {
    print_help();
    return Ok(ConsoleAction::ExitOk);
  }

  if let Some(i) = args.iter().position(|a| a == "--killswitch") {
    return run_killswitch(cfg, &args[i + 1..]);
  }

  if let Some(i) = args.iter().position(|a| a == "--incidents") {
    return run_incidents(&args[i + 1..]);
  }

  if let Some(i) = args.iter().position(|a| a == "--simulate") {
    return run_simulate(cfg, &args[i + 1..]);
  }

  Ok(ConsoleAction::RunAgent)
}

fn run_killswitch(cfg: &Config, tail: &[String]) -> anyhow::Result<ConsoleAction> {
  if !cfg.killswitch.enabled {
    println!("Kill switch is disabled in config (`killswitch.enabled = false`).");
    return Ok(ConsoleAction::ExitOk);
  }

  let sub = tail.first().map(|s| s.as_str()).unwrap_or("");
  match sub {
    "on" => {
      if let Err(e) = kill_switch::enable_manual() {
        print_admin_hint(&e);
        return Err(e);
      }
      tracing::warn!(group = kill_switch::FIREWALL_RULE_GROUP, "manual kill switch enabled");
      println!("Kill switch enabled: ALL inbound + outbound traffic is now blocked.");
      Ok(ConsoleAction::ExitOk)
    }
    "off" => {
      if let Err(e) = kill_switch::disable_with_reason("manual_cli", None) {
        print_admin_hint(&e);
        return Err(e);
      }
      tracing::info!(group = kill_switch::FIREWALL_RULE_GROUP, "kill switch disabled");
      println!("Kill switch disabled: networking should be restored.");
      Ok(ConsoleAction::ExitOk)
    }
    "status" => {
      match kill_switch::status() {
        Ok(st) => print_status(&st),
        Err(e) => {
          print_admin_hint(&e);
          return Err(e);
        }
      }
      Ok(ConsoleAction::ExitOk)
    }
    "keep-locked" => {
      let val = tail.get(1).map(|s| s.as_str()).unwrap_or("");
      let keep_locked = parse_bool(val).ok_or_else(|| {
        anyhow::anyhow!("expected `true` or `false` for `--killswitch keep-locked`")
      })?;
      if let Err(e) = kill_switch::set_keep_locked(keep_locked) {
        print_admin_hint(&e);
        return Err(e);
      }
      println!("keep_locked set to {keep_locked}.");
      Ok(ConsoleAction::ExitOk)
    }
    _ => {
      eprintln!("Unknown `--killswitch` subcommand. Expected: on|off|status|keep-locked");
      print_help();
      Ok(ConsoleAction::ExitOk)
    }
  }
}

fn run_simulate(cfg: &Config, tail: &[String]) -> anyhow::Result<ConsoleAction> {
  let sub = tail.first().map(|s| s.as_str()).unwrap_or("");
  match sub {
    "red" => {
      // Alias for `--simulate chain-red` to ensure simulations go through the same pipeline.
      let pid = 4242;
      let base = now_unix_ms();
      let image = "C:\\Temp\\evil.exe".to_string();
      let file_path = format!("{}\\Google\\Chrome\\User Data\\Default\\Login Data", localappdata());

      let events = vec![
        Event::ProcessStart {
          pid,
          ppid: 0,
          image_path: image.clone(),
          signer_publisher: None,
          timestamp_unix_ms: base,
        },
        Event::FileAccess {
          pid,
          image_path: Some(image.clone()),
          file_path: file_path.clone(),
          access: FileAccessType::Read,
          timestamp_unix_ms: base + 1_000,
        },
        Event::NetConnect {
          pid,
          image_path: Some(image),
          dest_ip: "1.2.3.4".to_string(),
          dest_port: 443,
          dest_host: None,
          protocol: "tcp".to_string(),
          timestamp_unix_ms: base + 2_000,
        },
      ];

      let incident_ids = run_events_through_pipeline(cfg, events)?;
      let incident_id = incident_ids.first().cloned().unwrap_or_default();

      println!("Simulated RED chain: incident_id={incident_id}");
      println!(
        "If auto-trigger is enabled, kill switch should be ON. Failsafe: {} minutes (unless keep_locked=true).",
        cfg.killswitch.failsafe_minutes
      );
      println!("Waiting for failsafe restore (Ctrl+C to exit early)...");

      let (stop_tx, stop_rx) = mpsc::channel::<()>();
      let tx = stop_tx.clone();
      ctrlc::set_handler(move || {
        let _ = tx.send(());
      })?;

      loop {
        if stop_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
          println!("Exiting.");
          break;
        }

        let _ = kill_switch::poll_failsafe();

        let st = match kill_switch::status() {
          Ok(s) => s,
          Err(e) => {
            print_admin_hint(&e);
            println!("Unable to read kill switch status; exiting.");
            break;
          }
        };

        if !st.enabled && !st.rules_present {
          println!("Kill switch appears OFF; network should be restored.");
          break;
        }
      }

      Ok(ConsoleAction::ExitOk)
    }
    "file-access-chrome" => {
      let pid = 4242;
      let base = now_unix_ms();
      let image = "C:\\Temp\\evil.exe".to_string();
      let file_path = format!("{}\\Google\\Chrome\\User Data\\Default\\Login Data", localappdata());

      let events = vec![
        Event::ProcessStart {
          pid,
          ppid: 0,
          image_path: image.clone(),
          signer_publisher: None,
          timestamp_unix_ms: base,
        },
        Event::FileAccess {
          pid,
          image_path: Some(image),
          file_path,
          access: FileAccessType::Read,
          timestamp_unix_ms: base + 1_000,
        },
      ];

      let incident_ids = run_events_through_pipeline(cfg, events)?;
      if incident_ids.is_empty() {
        println!("No incidents generated.");
      } else {
        println!("Generated incidents: {}", incident_ids.join(", "));
      }
      Ok(ConsoleAction::ExitOk)
    }
    "net-connect" => {
      let pid = 4242;
      let base = now_unix_ms();
      let image = "C:\\Temp\\evil.exe".to_string();

      let events = vec![
        Event::ProcessStart {
          pid,
          ppid: 0,
          image_path: image.clone(),
          signer_publisher: None,
          timestamp_unix_ms: base,
        },
        Event::NetConnect {
          pid,
          image_path: Some(image),
          dest_ip: "1.2.3.4".to_string(),
          dest_port: 443,
          dest_host: None,
          protocol: "tcp".to_string(),
          timestamp_unix_ms: base + 1_000,
        },
      ];

      let incident_ids = run_events_through_pipeline(cfg, events)?;
      if incident_ids.is_empty() {
        println!("No incidents generated.");
      } else {
        println!("Generated incidents: {}", incident_ids.join(", "));
      }
      Ok(ConsoleAction::ExitOk)
    }
    "chain-red" => {
      let pid = 4242;
      let base = now_unix_ms();
      let image = "C:\\Temp\\evil.exe".to_string();
      let file_path = format!("{}\\Google\\Chrome\\User Data\\Default\\Login Data", localappdata());

      let events = vec![
        Event::ProcessStart {
          pid,
          ppid: 0,
          image_path: image.clone(),
          signer_publisher: None,
          timestamp_unix_ms: base,
        },
        Event::FileAccess {
          pid,
          image_path: Some(image.clone()),
          file_path: file_path.clone(),
          access: FileAccessType::Read,
          timestamp_unix_ms: base + 1_000,
        },
        Event::NetConnect {
          pid,
          image_path: Some(image),
          dest_ip: "1.2.3.4".to_string(),
          dest_port: 443,
          dest_host: None,
          protocol: "tcp".to_string(),
          timestamp_unix_ms: base + 2_000,
        },
      ];

      let incident_ids = run_events_through_pipeline(cfg, events)?;
      if incident_ids.is_empty() {
        println!("No incidents generated.");
      } else {
        println!("Generated incidents: {}", incident_ids.join(", "));
      }
      Ok(ConsoleAction::ExitOk)
    }
    _ => {
      eprintln!("Unknown `--simulate` subcommand. Expected: red|file-access-chrome|net-connect|chain-red");
      print_help();
      Ok(ConsoleAction::ExitOk)
    }
  }
}

fn run_incidents(tail: &[String]) -> anyhow::Result<ConsoleAction> {
  let sub = tail.first().map(|s| s.as_str()).unwrap_or("");
  match sub {
    "list" => {
      let limit = parse_limit(tail).unwrap_or(10);
      let items = incident_store::list_recent(limit)?;
      if items.is_empty() {
        println!("No incidents found.");
        return Ok(ConsoleAction::ExitOk);
      }

      println!("Last {}/{} incidents:", items.len(), limit);
      for it in items {
        println!(
          "- {} severity={:?} created_at_unix_ms={} rules={}",
          it.incident_id,
          it.severity,
          it.created_at_unix_ms,
          it.rule_ids.join(",")
        );
      }
      Ok(ConsoleAction::ExitOk)
    }
    _ => {
      eprintln!("Unknown `--incidents` subcommand. Expected: list [--limit N]");
      print_help();
      Ok(ConsoleAction::ExitOk)
    }
  }
}

fn parse_limit(args: &[String]) -> Option<usize> {
  let mut i = 0;
  while i < args.len() {
    if args[i] == "--limit" {
      return args.get(i + 1).and_then(|s| s.parse::<usize>().ok());
    }
    i += 1;
  }
  None
}

fn run_events_through_pipeline(cfg: &Config, events: Vec<Event>) -> anyhow::Result<Vec<String>> {
  let mut engine = crate::rules_engine::Engine::new();
  let incidents = engine.process(cfg, &events)?;
  let mut ids = Vec::new();
  for mut inc in incidents {
    ids.push(inc.incident_id.clone());
    crate::response_engine::handle_incident(cfg, &mut inc)?;
  }
  Ok(ids)
}

fn localappdata() -> String {
  std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Users\\User\\AppData\\Local".to_string())
}

fn parse_bool(s: &str) -> Option<bool> {
  match s {
    "true" | "1" | "yes" | "on" => Some(true),
    "false" | "0" | "no" | "off" => Some(false),
    _ => None,
  }
}

fn strip_console_flag(args: &[String]) -> Vec<String> {
  args.iter().filter(|a| a.as_str() != "--console").cloned().collect()
}

fn print_help() {
  println!("AI Defender (console mode)");
  println!("Commands:");
  println!("  --killswitch on");
  println!("  --killswitch off");
  println!("  --killswitch status");
  println!("  --killswitch keep-locked true|false");
  println!("  --simulate red");
  println!("  --simulate file-access-chrome");
  println!("  --simulate net-connect");
  println!("  --simulate chain-red");
  println!("  --incidents list [--limit N]");
}

fn print_status(st: &kill_switch::KillSwitchStatus) {
  let effective = match (st.enabled, st.rules_present) {
    (true, true) => "ENABLED (network locked)",
    (false, false) => "DISABLED (network allowed)",
    (true, false) => "INCONSISTENT (state ON, rules missing)",
    (false, true) => "INCONSISTENT (state OFF, rules present)",
  };

  println!("Kill switch: {effective}");
  if let Some(b) = st.firewall_backend {
    println!("Firewall backend: {:?}", b);
  }
  println!("Keep locked: {}", st.keep_locked);
  println!("Mode: {:?}", st.enabled_mode);

  if let Some(deadline) = st.failsafe_deadline_unix_ms {
    let now = now_unix_ms();
    if deadline > now {
      let remaining_ms = deadline - now;
      let remaining_min = (remaining_ms + 59_999) / 60_000;
      println!("Failsafe: auto-restore in ~{remaining_min} minute(s) (AUTO mode only).");
    } else {
      println!("Failsafe: deadline passed (reconcile will restore on startup if still locked).");
    }
  } else {
    println!("Failsafe: none");
  }

  if let Some(id) = &st.last_incident_id {
    println!("Last incident_id: {id}");
  }

  if st.enabled && st.enabled_mode == Some(kill_switch::KillSwitchMode::Manual) {
    println!("Note: manual lock never auto-restores.");
  }
}

fn print_admin_hint(e: &anyhow::Error) {
  let msg = e.to_string();
  if msg.contains("rule name collision") {
    eprintln!("Kill switch rule name collision detected.");
    eprintln!(
      "A firewall rule with the same name exists but is not in group `AI_DEFENDER_KILLSWITCH`."
    );
    eprintln!("For safety, AI Defender will not modify or delete that rule.");
    return;
  }
  if msg.contains("Access is denied")
    || msg.contains("E_ACCESSDENIED")
    || msg.contains("0x80070005")
    || msg.contains("requires elevation")
  {
    eprintln!("Hint: firewall changes usually require Administrator privileges.");
    eprintln!("Try running this terminal as Administrator and re-run the command.");
  }
}

fn now_unix_ms() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as u64
}
