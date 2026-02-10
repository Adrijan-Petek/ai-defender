mod signature;

use agent_core::types::{now_unix_ms, Evidence, Finding, Incident, Severity};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
  Quick,
  Full,
}

impl ScanMode {
  pub fn from_args(args: &[String]) -> anyhow::Result<Self> {
    if args.iter().any(|a| a == "--quick") {
      return Ok(Self::Quick);
    }
    if args.iter().any(|a| a == "--full") {
      return Ok(Self::Full);
    }
    Err(anyhow::anyhow!("expected `--quick` or `--full`"))
  }
}

#[derive(Debug, Clone)]
struct ScanConfig {
  excludes: Vec<String>,
  cancel_file: Option<String>,
}

pub fn run(mode: ScanMode) -> anyhow::Result<()> {
  set_low_priority();
  let args: Vec<String> = std::env::args().collect();
  let cfg = parse_scan_config(&args);

  tracing_subscriber::fmt()
    .with_ansi(false)
    .with_target(false)
    .init();

  println!("AI Defender Scanner starting: mode={mode:?}");

  let roots = match mode {
    ScanMode::Quick => quick_roots(),
    ScanMode::Full => full_roots(),
  };

  let excludes: Vec<String> = cfg
    .excludes
    .iter()
    .map(|s| s.to_ascii_lowercase())
    .collect();

  let mut scanned: u64 = 0;
  let mut findings: Vec<Finding> = Vec::new();
  let mut seen_hashes: HashSet<String> = HashSet::new();

  for root in roots {
    if should_cancel(&cfg) {
      println!("Scan canceled by user.");
      return Ok(());
    }

    if root.as_os_str().is_empty() || !root.exists() {
      continue;
    }

    for entry in WalkDir::new(&root)
      .follow_links(false)
      .into_iter()
      .flatten()
    {
      if should_cancel(&cfg) {
        println!("Scan canceled by user.");
        return Ok(());
      }

      let p = entry.path();
      if entry.file_type().is_dir() {
        if is_excluded(&excludes, p) {
          continue;
        }
        continue;
      }

      scanned += 1;
      if scanned.is_multiple_of(250) {
        println!(
          "PROGRESS scanned={scanned} findings={} current={}",
          findings.len(),
          safe_filename(p)
        );
      }

      if !is_executable_candidate(p) {
        continue;
      }
      if is_excluded(&excludes, p) {
        continue;
      }

      if let Ok(mut fs) = scan_file(p) {
        for f in fs.drain(..) {
          if let Some(hash) = extract_sha256(&f) {
            if !seen_hashes.insert(hash) {
              continue;
            }
          }
          findings.push(f);
        }
      }
    }
  }

  if findings.is_empty() {
    println!("Scan complete: no findings. scanned={scanned}");
    return Ok(());
  }

  let mut incident = Incident::new(findings);
  incident.severity = Severity::Yellow;
  incident.actions_taken.push("scan_report_only".to_string());
  let id = incident.incident_id.clone();

  let path = agent_core::incident_store::store_incident(&incident)?;
  println!(
    "Scan complete: incident_id={id} severity=yellow stored={}",
    path.display()
  );
  Ok(())
}

fn parse_scan_config(args: &[String]) -> ScanConfig {
  let mut excludes = Vec::new();
  let mut cancel_file = None;
  let mut i = 0;
  while i < args.len() {
    match args[i].as_str() {
      "--exclude" => {
        if let Some(v) = args.get(i + 1) {
          excludes.push(v.clone());
          i += 2;
          continue;
        }
      }
      "--cancel-file" => {
        if let Some(v) = args.get(i + 1) {
          cancel_file = Some(v.clone());
          i += 2;
          continue;
        }
      }
      _ => {}
    }
    i += 1;
  }
  ScanConfig {
    excludes,
    cancel_file,
  }
}

fn should_cancel(cfg: &ScanConfig) -> bool {
  cfg
    .cancel_file
    .as_deref()
    .is_some_and(|p| Path::new(p).exists())
}

fn is_excluded(excludes: &[String], path: &Path) -> bool {
  let p = path.to_string_lossy().to_ascii_lowercase();
  excludes
    .iter()
    .any(|ex| !ex.trim().is_empty() && p.starts_with(ex))
}

fn quick_roots() -> Vec<PathBuf> {
  let mut roots = Vec::new();
  roots.extend(startup_folders());

  if let Ok(pf) = std::env::var("ProgramFiles") {
    roots.push(PathBuf::from(pf));
  }
  if let Ok(pfx) = std::env::var("ProgramFiles(x86)") {
    roots.push(PathBuf::from(pfx));
  }
  if let Ok(appdata) = std::env::var("APPDATA") {
    roots.push(PathBuf::from(&appdata));
    roots.push(
      PathBuf::from(&appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu"),
    );
  }
  if let Ok(local) = std::env::var("LOCALAPPDATA") {
    roots.push(PathBuf::from(&local));
    roots.extend(browser_extension_roots(&local));
  }

  roots
}

fn full_roots() -> Vec<PathBuf> {
  fixed_drives()
}

fn startup_folders() -> Vec<PathBuf> {
  let mut out = Vec::new();
  if let Ok(appdata) = std::env::var("APPDATA") {
    out.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
  }
  if let Ok(pd) = std::env::var("ProgramData") {
    out.push(PathBuf::from(pd).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
  }
  out
}

fn browser_extension_roots(localappdata: &str) -> Vec<PathBuf> {
  let l = PathBuf::from(localappdata);
  vec![
    l.join("Google\\Chrome\\User Data\\Default\\Extensions"),
    l.join("Microsoft\\Edge\\User Data\\Default\\Extensions"),
    l.join("BraveSoftware\\Brave-Browser\\User Data\\Default\\Extensions"),
  ]
}

fn is_executable_candidate(p: &Path) -> bool {
  let ext = p
    .extension()
    .and_then(|s| s.to_str())
    .unwrap_or("")
    .to_ascii_lowercase();
  matches!(
    ext.as_str(),
    "exe" | "dll" | "sys" | "ps1" | "js" | "vbs" | "bat" | "cmd"
  )
}

fn safe_filename(p: &Path) -> String {
  p.file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("<file>")
    .to_string()
}

fn scan_file(path: &Path) -> anyhow::Result<Vec<Finding>> {
  let mut findings = Vec::new();
  let ts = now_unix_ms();

  let sha256 = sha256_hex(path).ok();
  let signed = signature::is_trusted_signed(path).unwrap_or(false);

  if !signed && is_executable_candidate(path) {
    findings.push(Finding {
      rule_id: "S001".to_string(),
      severity: Severity::Yellow,
      description: "Unsigned executable/script found".to_string(),
      evidence: vec![Evidence::Note {
        message: format!(
          "path={} sha256={}",
          path.to_string_lossy(),
          sha256.clone().unwrap_or_else(|| "<unknown>".to_string())
        ),
      }],
      timestamp_unix_ms: ts,
    });
  }

  if is_user_writable_location(path) && is_executable_candidate(path) {
    findings.push(Finding {
      rule_id: "S002".to_string(),
      severity: Severity::Yellow,
      description: "Executable in user-writable directory".to_string(),
      evidence: vec![Evidence::Note {
        message: format!("path={}", path.to_string_lossy()),
      }],
      timestamp_unix_ms: ts,
    });
  }

  if is_in_startup_folder(path) && is_executable_candidate(path) {
    findings.push(Finding {
      rule_id: "S003".to_string(),
      severity: Severity::Yellow,
      description: "Executable in Startup folder (persistence location)".to_string(),
      evidence: vec![Evidence::Note {
        message: format!("path={}", path.to_string_lossy()),
      }],
      timestamp_unix_ms: ts,
    });
  }

  Ok(findings)
}

fn extract_sha256(f: &Finding) -> Option<String> {
  for e in &f.evidence {
    if let Evidence::Note { message } = e {
      if let Some(i) = message.find("sha256=") {
        return Some(message[i + 7..].trim().to_string());
      }
    }
  }
  None
}

fn sha256_hex(path: &Path) -> anyhow::Result<String> {
  let mut file = fs::File::open(path)?;
  let mut hasher = Sha256::new();
  let mut buf = [0u8; 64 * 1024];
  loop {
    let n = file.read(&mut buf)?;
    if n == 0 {
      break;
    }
    hasher.update(&buf[..n]);
  }
  Ok(format!("{:x}", hasher.finalize()))
}

fn is_in_startup_folder(path: &Path) -> bool {
  let p = path.to_string_lossy().to_ascii_lowercase();
  startup_folders()
    .into_iter()
    .filter_map(|d| d.to_str().map(|s| s.to_ascii_lowercase()))
    .any(|s| p.starts_with(&s))
}

fn is_user_writable_location(path: &Path) -> bool {
  let p = path.to_string_lossy().to_ascii_lowercase();
  let candidates = [
    std::env::var("TEMP").ok(),
    std::env::var("TMP").ok(),
    std::env::var("APPDATA").ok(),
    std::env::var("LOCALAPPDATA").ok(),
  ];
  candidates
    .into_iter()
    .flatten()
    .map(|s| s.to_ascii_lowercase())
    .any(|prefix| !prefix.is_empty() && p.starts_with(&prefix))
}

fn fixed_drives() -> Vec<PathBuf> {
  #[cfg(windows)]
  {
    signature::fixed_drives()
  }
  #[cfg(not(windows))]
  {
    vec![PathBuf::from("/")]
  }
}

fn set_low_priority() {
  #[cfg(windows)]
  {
    let _ = signature::set_low_priority();
  }
}
