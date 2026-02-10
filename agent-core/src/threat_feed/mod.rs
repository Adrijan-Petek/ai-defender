use crate::paths;
use crate::types::now_unix_ms;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

pub mod schema;
pub mod verify;

use schema::ThreatFeedBundle;

// Threat feed client interface (disabled by default).
//
// v1 does not perform outbound network calls automatically. Paid services may later provide an
// implementation that downloads signed bundles, but the agent must remain fully functional offline.
pub struct DownloadedBundle {
  pub bundle_json: Vec<u8>,
  pub signature: Vec<u8>,
}

pub trait ThreatFeedClient {
  fn fetch_latest(&self) -> anyhow::Result<DownloadedBundle>;
}

pub struct DisabledClient;

impl ThreatFeedClient for DisabledClient {
  fn fetch_latest(&self) -> anyhow::Result<DownloadedBundle> {
    anyhow::bail!("threat feed download is disabled by default; use offline import")
  }
}

#[derive(Debug, Clone)]
pub struct FeedStatus {
  pub installed: bool,
  pub verified: bool,
  pub version: Option<u64>,
  pub installed_at_unix_ms: Option<u64>,
  pub checked_at_unix_ms: u64,
  pub reason: Option<String>,
}

impl FeedStatus {
  pub fn none(reason: Option<String>) -> Self {
    Self {
      installed: false,
      verified: false,
      version: None,
      installed_at_unix_ms: None,
      checked_at_unix_ms: now_unix_ms(),
      reason,
    }
  }
}

pub fn status(base: &Path) -> FeedStatus {
  let bundle_path = paths::threat_feed_bundle_path(base);
  let sig_path = paths::threat_feed_sig_path(base);

  if !bundle_path.exists() || !sig_path.exists() {
    let st = FeedStatus::none(Some("no bundle installed".to_string()));
    let _ = write_state(base, &st);
    return st;
  }

  match verify_files(&bundle_path, &sig_path) {
    Ok(bundle) => {
      let _ = write_last_good(base, &bundle_path, &sig_path);
      let installed_at = bundle_mtime_unix_ms(&bundle_path);
      let st = FeedStatus {
        installed: true,
        verified: true,
        version: Some(bundle.version),
        installed_at_unix_ms: installed_at,
        checked_at_unix_ms: now_unix_ms(),
        reason: None,
      };
      let _ = write_state(base, &st);
      st
    }
    Err(e) => {
      // If the current bundle is invalid (e.g., manual corruption), fall back to last-known-good.
      if let Ok(bundle) = verify_last_good(base) {
        let st = FeedStatus {
          installed: true,
          verified: true,
          version: Some(bundle.version),
          installed_at_unix_ms: bundle_mtime_unix_ms(&bundle_path),
          checked_at_unix_ms: now_unix_ms(),
          reason: Some("current bundle invalid; using last known good".to_string()),
        };
        let _ = write_state(base, &st);
        return st;
      }

      let st = FeedStatus {
        installed: true,
        verified: false,
        version: None,
        installed_at_unix_ms: bundle_mtime_unix_ms(&bundle_path),
        checked_at_unix_ms: now_unix_ms(),
        reason: Some(format!("invalid bundle: {e:#}")),
      };
      let _ = write_state(base, &st);
      st
    }
  }
}

pub fn verify_files(bundle_path: &Path, sig_path: &Path) -> anyhow::Result<ThreatFeedBundle> {
  let bundle_json = fs::read(bundle_path)
    .with_context(|| format!("read {}", bundle_path.display()))?;
  let sig = fs::read(sig_path).with_context(|| format!("read {}", sig_path.display()))?;

  // Signature file may be raw 64 bytes or base64url text.
  let sig_bytes = if sig.len() == 64 {
    sig
  } else {
    let text = String::from_utf8(sig).context("signature file must be raw bytes or UTF-8")?;
    verify::decode_sig_base64url(&text)?
  };

  verify::verify_bundle_signature(&bundle_json, &sig_bytes)?;
  let bundle: ThreatFeedBundle =
    serde_json::from_slice(&bundle_json).context("parse bundle JSON")?;

  // Basic schema sanity.
  if bundle.version == 0 {
    anyhow::bail!("bundle version must be > 0");
  }
  if bundle.created_at_unix_ms == 0 {
    anyhow::bail!("bundle created_at_unix_ms must be > 0");
  }

  Ok(bundle)
}

pub fn import(base: &Path, src_bundle: &Path, src_sig: Option<&Path>) -> anyhow::Result<FeedStatus> {
  let (bundle_path, sig_path) = resolve_import_paths(src_bundle, src_sig)?;
  let bundle = verify_files(&bundle_path, &sig_path).context("verify bundle and signature")?;

  let current = current_version(base).unwrap_or(0);
  if bundle.version <= current {
    anyhow::bail!("bundle version {} is not newer than installed {}", bundle.version, current);
  }

  let dst_dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dst_dir).with_context(|| format!("create {}", dst_dir.display()))?;

  // Write to staging and then replace to avoid partial updates.
  let staging_bundle = dst_dir.join("bundle.json.new");
  let staging_sig = dst_dir.join("bundle.sig.new");
  fs::copy(&bundle_path, &staging_bundle).with_context(|| "stage bundle.json")?;
  fs::copy(&sig_path, &staging_sig).with_context(|| "stage bundle.sig")?;

  // Final paths.
  let dst_bundle = paths::threat_feed_bundle_path(base);
  let dst_sig = paths::threat_feed_sig_path(base);
  replace_file(&staging_bundle, &dst_bundle)?;
  replace_file(&staging_sig, &dst_sig)?;

  // Persist last-known-good after a successful import.
  write_last_good(base, &dst_bundle, &dst_sig)?;

  let st = FeedStatus {
    installed: true,
    verified: true,
    version: Some(bundle.version),
    installed_at_unix_ms: bundle_mtime_unix_ms(&dst_bundle),
    checked_at_unix_ms: now_unix_ms(),
    reason: None,
  };
  write_state(base, &st)?;
  Ok(st)
}

fn current_version(base: &Path) -> Option<u64> {
  let bundle_path = paths::threat_feed_bundle_path(base);
  let sig_path = paths::threat_feed_sig_path(base);
  let b = verify_files(&bundle_path, &sig_path).ok()?;
  Some(b.version)
}

fn resolve_import_paths(src_bundle: &Path, src_sig: Option<&Path>) -> anyhow::Result<(PathBuf, PathBuf)> {
  if let Some(sig) = src_sig {
    return Ok((src_bundle.to_path_buf(), sig.to_path_buf()));
  }

  if src_bundle.is_dir() {
    let bundle = src_bundle.join("bundle.json");
    let sig = src_bundle.join("bundle.sig");
    return Ok((bundle, sig));
  }

  // If a file was provided, look for common signature sidecars.
  let bundle = src_bundle.to_path_buf();
  let sig1 = PathBuf::from(format!("{}.sig", bundle.display()));
  if sig1.exists() {
    return Ok((bundle, sig1));
  }

  if let Some(parent) = bundle.parent() {
    let sig2 = parent.join("bundle.sig");
    if sig2.exists() {
      return Ok((bundle, sig2));
    }
  }

  anyhow::bail!("signature path not provided and no adjacent signature file found");
}

fn replace_file(staging: &Path, dst: &Path) -> anyhow::Result<()> {
  // Preserve last known good: do not delete the destination until the staged file is in place.
  let bak = dst.with_extension("bak");
  if bak.exists() {
    let _ = fs::remove_file(&bak);
  }

  if dst.exists() {
    fs::rename(dst, &bak).with_context(|| format!("backup {}", dst.display()))?;
  }

  match fs::rename(staging, dst) {
    Ok(()) => {
      if bak.exists() {
        let _ = fs::remove_file(&bak);
      }
      Ok(())
    }
    Err(e) => {
      // Attempt rollback.
      if bak.exists() {
        let _ = fs::rename(&bak, dst);
      }
      Err(e).with_context(|| format!("replace {}", dst.display()))
    }
  }?;
  Ok(())
}

fn write_state(base: &Path, st: &FeedStatus) -> anyhow::Result<()> {
  let dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
  let path = paths::threat_feed_state_path(base);

  let content = format!(
    "installed = {}\nverified = {}\nversion = {}\ninstalled_at_unix_ms = {}\nchecked_at_unix_ms = {}\nreason = {}\n",
    st.installed,
    st.verified,
    toml_u64_or_null(st.version),
    toml_u64_or_null(st.installed_at_unix_ms),
    st.checked_at_unix_ms,
    toml_string_or_null(st.reason.as_deref()),
  );

  fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
  Ok(())
}

fn toml_string_or_null(v: Option<&str>) -> String {
  match v {
    Some(s) => format!("\"{}\"", s.replace('"', "\\\"")),
    None => "null".to_string(),
  }
}

fn toml_u64_or_null(v: Option<u64>) -> String {
  match v {
    Some(x) => x.to_string(),
    None => "null".to_string(),
  }
}

fn bundle_mtime_unix_ms(path: &Path) -> Option<u64> {
  let meta = fs::metadata(path).ok()?;
  let m = meta.modified().ok()?;
  let dur = m.duration_since(std::time::UNIX_EPOCH).ok()?;
  Some(dur.as_millis() as u64)
}

fn last_good_bundle_path(base: &Path) -> PathBuf {
  paths::threat_feed_dir(base).join("bundle.json.last-good")
}

fn last_good_sig_path(base: &Path) -> PathBuf {
  paths::threat_feed_dir(base).join("bundle.sig.last-good")
}

fn write_last_good(base: &Path, bundle: &Path, sig: &Path) -> anyhow::Result<()> {
  let dir = paths::threat_feed_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
  fs::copy(bundle, last_good_bundle_path(base)).context("write last-good bundle")?;
  fs::copy(sig, last_good_sig_path(base)).context("write last-good sig")?;
  Ok(())
}

fn verify_last_good(base: &Path) -> anyhow::Result<ThreatFeedBundle> {
  let b = last_good_bundle_path(base);
  let s = last_good_sig_path(base);
  verify_files(&b, &s)
}
