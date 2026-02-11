use crate::config::Config;
use crate::incident_store;
use crate::kill_switch;
use crate::runtime;
use crate::types::{now_unix_ms, Event, FileAccessType};
use crate::{license, paths, threat_feed};
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

  if let Some(i) = args.iter().position(|a| a == "--license") {
    return run_license(&args[i + 1..]);
  }

  if let Some(i) = args.iter().position(|a| a == "--feed") {
    return run_feed(cfg, &args[i + 1..]);
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
      if runtime::is_dry_run() {
        println!("DRY-RUN: would enable firewall kill switch (group AI_DEFENDER_KILLSWITCH).");
        return Ok(ConsoleAction::ExitOk);
      }
      tracing::warn!(
        group = kill_switch::FIREWALL_RULE_GROUP,
        "manual kill switch enabled"
      );
      println!("Kill switch enabled: ALL inbound + outbound traffic is now blocked.");
      Ok(ConsoleAction::ExitOk)
    }
    "off" => {
      if let Err(e) = kill_switch::disable_with_reason("manual_cli", None) {
        print_admin_hint(&e);
        return Err(e);
      }
      if runtime::is_dry_run() {
        println!("DRY-RUN: would remove firewall rules (group AI_DEFENDER_KILLSWITCH).");
        return Ok(ConsoleAction::ExitOk);
      }
      tracing::info!(
        group = kill_switch::FIREWALL_RULE_GROUP,
        "kill switch disabled"
      );
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
      if runtime::is_dry_run() {
        println!("DRY-RUN: would set keep_locked to {keep_locked}.");
        return Ok(ConsoleAction::ExitOk);
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

fn run_license(tail: &[String]) -> anyhow::Result<ConsoleAction> {
  let base = paths::base_dir()?;

  let sub = tail.first().map(|s| s.as_str()).unwrap_or("");
  match sub {
    "status" => {
      let st = license::status(&base);
      println!(
        "License: {}",
        match st.state {
          license::LicenseState::Community => "Community",
          license::LicenseState::ProActive => "Pro (active)",
          license::LicenseState::ProExpired => "Pro (expired)",
          license::LicenseState::ProInvalid => "Pro (invalid or not activated)",
        }
      );

      if let Some(id) = st.license_id.as_deref() {
        println!("License ID: {id}");
      }
      if let Some(plan) = st.plan.as_deref() {
        println!("Plan: {plan}");
      }
      if let Some(seats) = st.seats {
        println!("Seats: {seats} (server activation planned; offline mode is local-only)");
      }
      match st.expires_at_unix_seconds {
        Some(exp) => println!("Expires (unix seconds): {exp}"),
        None => println!("Expires: none"),
      }
      if let Some(ts) = st.last_verified_at_unix_seconds {
        println!("Last verified (unix seconds): {ts}");
      }
      println!("Checked at (unix seconds): {}", st.checked_at_unix_seconds);
      if let Some(r) = st.reason.as_deref() {
        println!("Note: {r}");
      }
      Ok(ConsoleAction::ExitOk)
    }
    "install" => {
      let json = tail.get(1).map(|s| s.as_str()).unwrap_or("");
      let sig = tail.get(2).map(|s| s.as_str()).unwrap_or("");
      if json.is_empty() || sig.is_empty() {
        anyhow::bail!("expected: --license install <path-to-license.json> <path-to-license.sig>");
      }
      let st =
        license::install_license(&base, std::path::Path::new(json), std::path::Path::new(sig))?;
      if runtime::is_dry_run() {
        println!("DRY-RUN: would install license.");
        return Ok(ConsoleAction::ExitOk);
      }
      println!(
        "Installed license. Status: {}",
        match st.state {
          license::LicenseState::Community => "Community",
          license::LicenseState::ProActive => "Pro (active)",
          license::LicenseState::ProExpired => "Pro (expired)",
          license::LicenseState::ProInvalid => "Pro (not activated)",
        }
      );
      Ok(ConsoleAction::ExitOk)
    }
    "activate" => {
      let st = license::activate(&base)?;
      if runtime::is_dry_run() {
        println!("DRY-RUN: would activate license on this device.");
        return Ok(ConsoleAction::ExitOk);
      }
      println!(
        "Activation complete. Status: {}",
        match st.state {
          license::LicenseState::Community => "Community",
          license::LicenseState::ProActive => "Pro (active)",
          license::LicenseState::ProExpired => "Pro (expired)",
          license::LicenseState::ProInvalid => "Pro (invalid)",
        }
      );
      Ok(ConsoleAction::ExitOk)
    }
    "deactivate" => {
      license::deactivate(&base)?;
      if runtime::is_dry_run() {
        println!("DRY-RUN: would deactivate this device.");
        return Ok(ConsoleAction::ExitOk);
      }
      println!("Deactivated this device (activation removed).");
      Ok(ConsoleAction::ExitOk)
    }
    _ => {
      eprintln!(
        "Unknown `--license` subcommand. Expected: status|install <json> <sig>|activate|deactivate"
      );
      print_help();
      Ok(ConsoleAction::ExitOk)
    }
  }
}

fn run_feed(cfg: &Config, tail: &[String]) -> anyhow::Result<ConsoleAction> {
  let base = paths::base_dir()?;

  let sub = tail.first().map(|s| s.as_str()).unwrap_or("");
  match sub {
    "status" => {
      let st = threat_feed::bundle_status_at(&base);
      if !st.present {
        println!("Threat feed: not installed");
        return Ok(ConsoleAction::ExitOk);
      }

      println!("Threat feed: installed");
      if let Some(v) = st.rules_version {
        println!("Rules version: {v}");
      }
      if let Some(ts) = st.created_at {
        println!("Created at (unix seconds): {ts}");
      }
      if let Some(ts) = st.verified_at {
        println!("Verified at (unix seconds): {ts}");
      }
      if let Some(ts) = st.last_refresh_attempt_at {
        println!("Last refresh attempt (unix seconds): {ts}");
      }
      if let Some(result) = st.last_refresh_result {
        println!("Last refresh result: {result}");
      }
      Ok(ConsoleAction::ExitOk)
    }
    "import" => {
      let b = tail.get(1).map(|s| s.as_str()).unwrap_or("");
      let s = tail.get(2).map(|s| s.as_str()).unwrap_or("");
      if b.is_empty() || s.is_empty() {
        anyhow::bail!("expected: --feed import <path-to-bundle.json> <path-to-bundle.sig>");
      }
      let st = threat_feed::import(&base, std::path::Path::new(b), std::path::Path::new(s))?;
      if runtime::is_dry_run() {
        println!("DRY-RUN: would install threat feed bundle.");
        return Ok(ConsoleAction::ExitOk);
      }
      println!("Imported threat feed bundle.");
      if let Some(v) = st.rules_version {
        println!("Rules version: {v}");
      }
      Ok(ConsoleAction::ExitOk)
    }
    "verify" => {
      let b = tail.get(1).map(|s| s.as_str()).unwrap_or("");
      let s = tail.get(2).map(|s| s.as_str()).unwrap_or("");
      if b.is_empty() || s.is_empty() {
        anyhow::bail!("expected: --feed verify <path-to-bundle.json> <path-to-bundle.sig>");
      }
      let bundle = threat_feed::verify_files(std::path::Path::new(b), std::path::Path::new(s))?;
      println!("Threat feed bundle verified.");
      println!("Bundle schema version: {}", bundle.version);
      println!("Rules version: {}", bundle.rules_version);
      println!("Created at (unix seconds): {}", bundle.created_at);
      Ok(ConsoleAction::ExitOk)
    }
    "refresh-now" => {
      let res = threat_feed::refresh_now(cfg, &base);
      if !res.attempted {
        println!("{}", res.reason);
        return Ok(ConsoleAction::ExitOk);
      }
      if runtime::is_dry_run() {
        println!("{}", res.reason);
        return Ok(ConsoleAction::ExitOk);
      }
      if res.success {
        println!("Threat feed refresh completed successfully.");
      } else {
        println!("Threat feed refresh failed: {}", res.reason);
      }
      Ok(ConsoleAction::ExitOk)
    }
    "auto-refresh" => {
      let nested = tail.get(1).map(|s| s.as_str()).unwrap_or("");
      if nested != "status" {
        anyhow::bail!("expected: --feed auto-refresh status");
      }
      let st = threat_feed::auto_refresh_status(cfg, &base);
      println!(
        "Auto refresh: {}",
        if st.enabled { "enabled" } else { "disabled" }
      );
      println!("Interval minutes: {}", st.interval_minutes);
      println!("Eligible now: {}", if st.eligible { "yes" } else { "no" });
      println!("Reason: {}", st.reason);
      match st.last_attempt_at {
        Some(ts) => println!("Last attempt (unix seconds): {ts}"),
        None => println!("Last attempt: none"),
      }
      match st.last_result {
        Some(v) => println!("Last result: {v}"),
        None => println!("Last result: none"),
      }
      Ok(ConsoleAction::ExitOk)
    }
    _ => {
      eprintln!(
        "Unknown `--feed` subcommand. Expected: status|import <bundle.json> <bundle.sig>|verify <bundle.json> <bundle.sig>|refresh-now|auto-refresh status"
      );
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
      let file_path = format!(
        "{}\\Google\\Chrome\\User Data\\Default\\Login Data",
        localappdata()
      );

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
      let file_path = format!(
        "{}\\Google\\Chrome\\User Data\\Default\\Login Data",
        localappdata()
      );

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
      let file_path = format!(
        "{}\\Google\\Chrome\\User Data\\Default\\Login Data",
        localappdata()
      );

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
      eprintln!(
        "Unknown `--simulate` subcommand. Expected: red|file-access-chrome|net-connect|chain-red"
      );
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
  args
    .iter()
    .filter(|a| a.as_str() != "--console" && a.as_str() != "--dry-run")
    .cloned()
    .collect()
}

fn print_help() {
  println!("AI Defender v{} (console mode)", env!("CARGO_PKG_VERSION"));
  println!("Commands:");
  println!("  --dry-run (global; logs actions without side effects)");
  println!("  --killswitch on");
  println!("  --killswitch off");
  println!("  --killswitch status");
  println!("  --killswitch keep-locked true|false");
  println!("  --license status");
  println!("  --license install <path-to-license.json> <path-to-license.sig>");
  println!("  --license activate");
  println!("  --license deactivate");
  println!("  --feed status");
  println!("  --feed import <path-to-bundle.json> <path-to-bundle.sig>");
  println!("  --feed verify <path-to-bundle.json> <path-to-bundle.sig>");
  println!("  --feed refresh-now");
  println!("  --feed auto-refresh status");
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
      let remaining_min = remaining_ms.div_ceil(60_000);
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

// NOTE: `now_unix_ms` is provided by `crate::types`.
