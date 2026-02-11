use crate::paths;
use crate::runtime;
use crate::types::{now_unix_ms, Event, FileAccessType};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static COLLECTOR: OnceLock<Mutex<SysmonCollector>> = OnceLock::new();

#[derive(Debug)]
struct SysmonCollector {
  last_record_id: u64,
  warned_missing: bool,
  initialized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SysmonBookmark {
  #[serde(default)]
  last_record_id: u64,
}

pub fn collect_once() -> anyhow::Result<Vec<Event>> {
  #[cfg(not(windows))]
  {
    return Ok(Vec::new());
  }

  #[cfg(windows)]
  {
    let base = paths::base_dir()?;
    if !runtime::is_dry_run() {
      fs::create_dir_all(&base)?;
    }
    let bookmark_path = paths::sysmon_bookmark_path(&base);

    let m = COLLECTOR.get_or_init(|| {
      Mutex::new(SysmonCollector {
        last_record_id: 0,
        warned_missing: false,
        initialized: false,
      })
    });

    let mut c = m.lock().unwrap();
    if !c.initialized {
      c.last_record_id = load_bookmark(&bookmark_path)
        .unwrap_or_default()
        .last_record_id;
      c.initialized = true;
    }

    let events = match poll_sysmon(&mut c) {
      Ok(evs) => evs,
      Err(e) => {
        if !c.warned_missing {
          tracing::warn!(
            error = ?e,
            "Sysmon collector unavailable (Sysmon not installed or access denied). Detection will run only on simulated events."
          );
          c.warned_missing = true;
        }
        Vec::new()
      }
    };

    if !events.is_empty() {
      let bm = SysmonBookmark {
        last_record_id: c.last_record_id,
      };
      if runtime::is_dry_run() {
        tracing::warn!(
          record_id = bm.last_record_id,
          "DRY-RUN: would update Sysmon bookmark"
        );
      } else {
        let _ = save_bookmark(&bookmark_path, &bm);
      }
    }

    Ok(events)
  }
}

#[cfg(windows)]
fn poll_sysmon(c: &mut SysmonCollector) -> anyhow::Result<Vec<Event>> {
  // Use a constant, sanitized query. No user input is interpolated besides last_record_id (u64).
  const LOG: &str = "Microsoft-Windows-Sysmon/Operational";
  let query = format!(
    "*[System[(EventID=1 or EventID=3 or EventID=11) and (EventRecordID > {})]]",
    c.last_record_id
  );

  let output = Command::new("wevtutil")
    .args([
      "qe",
      LOG,
      "/f:xml",
      "/rd:false",
      "/c:64",
      &format!("/q:{query}"),
    ])
    .output()?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    return Err(anyhow::anyhow!("wevtutil qe failed: {}", stderr.trim()));
  }

  let stdout = String::from_utf8_lossy(&output.stdout);
  let xml = format!("<Events>{}</Events>", stdout);
  parse_sysmon_xml(&xml, c)
}

#[cfg(windows)]
fn parse_sysmon_xml(xml: &str, c: &mut SysmonCollector) -> anyhow::Result<Vec<Event>> {
  use quick_xml::events::Event as XEvent;
  use quick_xml::Reader;

  let mut rdr = Reader::from_str(xml);
  rdr.trim_text(true);
  let mut buf = Vec::new();

  let mut events = Vec::new();

  // Current event fields.
  let mut in_event = false;
  let mut in_system = false;
  let mut in_event_data = false;
  let mut current_tag: Option<String> = None;
  let mut event_id: Option<u32> = None;
  let mut record_id: Option<u64> = None;
  let mut data_name: Option<String> = None;
  let mut data: std::collections::HashMap<String, String> = std::collections::HashMap::new();

  fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
  }

  loop {
    match rdr.read_event_into(&mut buf) {
      Ok(XEvent::Start(e)) => {
        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        let lname = local(&name);
        if lname == "Event" {
          in_event = true;
          event_id = None;
          record_id = None;
          data.clear();
          continue;
        }

        if !in_event {
          continue;
        }

        if lname == "System" {
          in_system = true;
          continue;
        }
        if lname == "EventData" {
          in_event_data = true;
          continue;
        }

        if in_system {
          current_tag = Some(lname.to_string());
        } else if in_event_data && lname == "Data" {
          data_name = e
            .attributes()
            .flatten()
            .find(|a| a.key.as_ref() == b"Name")
            .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
        }
      }
      Ok(XEvent::Text(t)) => {
        if !in_event {
          continue;
        }
        let text = t.unescape().unwrap_or_default().to_string();

        if in_system {
          if let Some(tag) = current_tag.as_deref() {
            match tag {
              "EventID" => {
                event_id = text.trim().parse::<u32>().ok();
              }
              "EventRecordID" => {
                record_id = text.trim().parse::<u64>().ok();
              }
              _ => {}
            }
          }
        } else if in_event_data {
          if let Some(k) = data_name.take() {
            data.insert(k, text);
          }
        }
      }
      Ok(XEvent::End(e)) => {
        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        let lname = local(&name);
        if lname == "System" {
          in_system = false;
          current_tag = None;
        } else if lname == "EventData" {
          in_event_data = false;
        } else if lname == "Event" {
          in_event = false;

          if let (Some(eid), Some(rid)) = (event_id, record_id) {
            if rid > c.last_record_id {
              c.last_record_id = rid;
            }
            if let Some(ev) = normalize_sysmon(eid, &data) {
              events.push(ev);
            }
          }
        }
      }
      Ok(XEvent::Eof) => break,
      Err(e) => return Err(anyhow::anyhow!("sysmon xml parse error: {e}")),
      _ => {}
    }
    buf.clear();
  }

  Ok(events)
}

#[cfg(windows)]
fn normalize_sysmon(
  event_id: u32,
  data: &std::collections::HashMap<String, String>,
) -> Option<Event> {
  let ts = now_unix_ms();
  match event_id {
    1 => {
      let pid = data.get("ProcessId")?.parse::<u32>().ok()?;
      let ppid = data
        .get("ParentProcessId")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
      let image = data.get("Image")?.to_string();
      let publisher = data.get("Company").cloned();
      Some(Event::ProcessStart {
        pid,
        ppid,
        image_path: image,
        signer_publisher: publisher,
        timestamp_unix_ms: ts,
      })
    }
    3 => {
      let pid = data.get("ProcessId")?.parse::<u32>().ok()?;
      let image = data.get("Image").cloned();
      let dest_ip = data.get("DestinationIp")?.to_string();
      let dest_port = data
        .get("DestinationPort")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
      let protocol = data
        .get("Protocol")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
      let host = data.get("DestinationHostname").cloned();
      Some(Event::NetConnect {
        pid,
        image_path: image,
        dest_ip,
        dest_port,
        dest_host: host,
        protocol,
        timestamp_unix_ms: ts,
      })
    }
    11 => {
      let pid = data.get("ProcessId")?.parse::<u32>().ok()?;
      let image = data.get("Image").cloned();
      let file = data.get("TargetFilename")?.to_string();
      Some(Event::FileAccess {
        pid,
        image_path: image,
        file_path: file,
        access: FileAccessType::Write,
        timestamp_unix_ms: ts,
      })
    }
    _ => None,
  }
}

fn load_bookmark(path: &std::path::Path) -> anyhow::Result<SysmonBookmark> {
  if !path.exists() {
    return Ok(SysmonBookmark::default());
  }
  let raw = fs::read_to_string(path)?;
  Ok(toml::from_str(&raw)?)
}

fn save_bookmark(path: &std::path::Path, bm: &SysmonBookmark) -> anyhow::Result<()> {
  let raw = toml::to_string_pretty(bm)?;
  write_atomic(path, &raw)
}

fn write_atomic(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("bookmark path has no parent: {}", path.display()))?;
  fs::create_dir_all(parent)?;

  let tmp = parent.join(format!(
    ".{}.tmp",
    path.file_name().unwrap_or_default().to_string_lossy()
  ));
  fs::write(&tmp, contents)?;
  fs::rename(&tmp, path)?;
  Ok(())
}
