use crate::paths;
use crate::types::now_unix_ms;
use anyhow::Context;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// Public-key only. Replace with the production public key for license verification.
// Base64url (no padding) encoded 32-byte Ed25519 public key.
const LICENSE_PUBKEY_B64URL: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseState {
  Community,
  ProActive,
  ProExpired,
  ProInvalid,
}

#[derive(Debug, Clone)]
pub struct LicenseStatus {
  pub state: LicenseState,
  pub license_id: Option<String>,
  pub plan: Option<String>,
  pub seats: Option<u32>,
  pub expires_at_unix_seconds: Option<u64>,
  pub last_verified_at_unix_seconds: Option<u64>,
  pub checked_at_unix_seconds: u64,
  pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayloadV1 {
  pub version: u32,
  pub license_id: String,
  pub user_id: String,
  pub plan: String,
  pub seats: u32,
  pub issued_at: u64,

  #[serde(default)]
  pub expires_at: Option<u64>,

  #[serde(default)]
  pub features: Vec<String>,

  #[serde(default)]
  pub issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivationState {
  device_id: String,
  activated_at: u64,
  license_id: String,
  last_verified_at: u64,
}

pub fn install_license(
  base: &Path,
  from_license_json: &Path,
  from_license_sig: &Path,
) -> anyhow::Result<LicenseStatus> {
  let payload_bytes = fs::read(from_license_json)
    .with_context(|| format!("read {}", from_license_json.display()))?;
  let sig_bytes = fs::read(from_license_sig)
    .with_context(|| format!("read {}", from_license_sig.display()))?;

  // Validate before copying.
  let (payload, state, reason) =
    validate_payload_and_signature(&payload_bytes, &sig_bytes)?;

  if state != LicenseState::ProActive && state != LicenseState::ProExpired {
    anyhow::bail!(reason.unwrap_or_else(|| "license validation failed".to_string()));
  }

  let lic_dir = paths::license_dir(base);
  fs::create_dir_all(&lic_dir).with_context(|| format!("create {}", lic_dir.display()))?;

  let dst_json = paths::license_json_path(base);
  let dst_sig = paths::license_sig_path(base);

  atomic_write_file(&dst_json, &payload_bytes)?;
  atomic_write_file(&dst_sig, &sig_bytes)?;

  // New license installed: require explicit activation. Do not auto-activate.
  let _ = write_status(
    base,
    &LicenseStatus {
      state: LicenseState::ProInvalid,
      license_id: Some(payload.license_id.clone()),
      plan: Some(payload.plan.clone()),
      seats: Some(payload.seats),
      expires_at_unix_seconds: payload.expires_at,
      last_verified_at_unix_seconds: None,
      checked_at_unix_seconds: now_unix_s(),
      reason: Some("license installed; activation required".to_string()),
    },
  );

  Ok(status(base))
}

pub fn activate(base: &Path) -> anyhow::Result<LicenseStatus> {
  let (payload_bytes, sig_bytes) = load_license_files(base)
    .context("load installed license")?;

  let (payload, state, reason) =
    validate_payload_and_signature(&payload_bytes, &sig_bytes)?;

  match state {
    LicenseState::ProExpired => {
      let st = LicenseStatus {
        state,
        license_id: Some(payload.license_id),
        plan: Some(payload.plan),
        seats: Some(payload.seats),
        expires_at_unix_seconds: payload.expires_at,
        last_verified_at_unix_seconds: None,
        checked_at_unix_seconds: now_unix_s(),
        reason,
      };
      write_status(base, &st)?;
      return Ok(st);
    }
    LicenseState::ProActive => {}
    _ => {
      anyhow::bail!(reason.unwrap_or_else(|| "invalid license".to_string()));
    }
  }

  // Ensure we have a stable local device id without fingerprinting.
  let dev_id = get_or_create_device_id(base)?;

  let now = now_unix_s();
  let act = ActivationState {
    device_id: dev_id,
    activated_at: now,
    license_id: payload.license_id.clone(),
    last_verified_at: now,
  };

  let act_path = paths::license_activation_path(base);
  let act_dir = paths::license_dir(base);
  fs::create_dir_all(&act_dir).with_context(|| format!("create {}", act_dir.display()))?;

  let json = serde_json::to_vec_pretty(&act).context("serialize activation.json")?;
  atomic_write_file(&act_path, &json)?;

  Ok(status(base))
}

pub fn deactivate(base: &Path) -> anyhow::Result<()> {
  let act_path = paths::license_activation_path(base);
  if act_path.exists() {
    fs::remove_file(&act_path).with_context(|| format!("delete {}", act_path.display()))?;
  }
  let st = status(base);
  let _ = write_status(base, &st);
  Ok(())
}

pub fn status(base: &Path) -> LicenseStatus {
  let checked = now_unix_s();

  let Ok((payload_bytes, sig_bytes)) = load_license_files(base) else {
    let st = LicenseStatus {
      state: LicenseState::Community,
      license_id: None,
      plan: None,
      seats: None,
      expires_at_unix_seconds: None,
      last_verified_at_unix_seconds: None,
      checked_at_unix_seconds: checked,
      reason: Some("no license installed".to_string()),
    };
    let _ = write_status(base, &st);
    return st;
  };

  let (payload, state, reason) =
    match validate_payload_and_signature(&payload_bytes, &sig_bytes) {
      Ok(x) => x,
      Err(e) => {
        let st = LicenseStatus {
          state: LicenseState::ProInvalid,
          license_id: None,
          plan: None,
          seats: None,
          expires_at_unix_seconds: None,
          last_verified_at_unix_seconds: None,
          checked_at_unix_seconds: checked,
          reason: Some(format!("invalid license: {e:#}")),
        };
        let _ = write_status(base, &st);
        return st;
      }
    };

  if state == LicenseState::ProExpired {
    let st = LicenseStatus {
      state,
      license_id: Some(payload.license_id),
      plan: Some(payload.plan),
      seats: Some(payload.seats),
      expires_at_unix_seconds: payload.expires_at,
      last_verified_at_unix_seconds: None,
      checked_at_unix_seconds: checked,
      reason,
    };
    let _ = write_status(base, &st);
    return st;
  }

  // Valid license: require activation.
  let act_path = paths::license_activation_path(base);
  let act = read_activation(&act_path);
  let activated = act
    .as_ref()
    .map(|a| a.license_id == payload.license_id)
    .unwrap_or(false);

  if !activated {
    let st = LicenseStatus {
      state: LicenseState::ProInvalid,
      license_id: Some(payload.license_id),
      plan: Some(payload.plan),
      seats: Some(payload.seats),
      expires_at_unix_seconds: payload.expires_at,
      last_verified_at_unix_seconds: act.as_ref().map(|a| a.last_verified_at),
      checked_at_unix_seconds: checked,
      reason: Some(
        "license is valid but not activated on this device (local activation only; server activation planned)"
          .to_string(),
      ),
    };
    let _ = write_status(base, &st);
    return st;
  }

  // Update last_verified_at for auditability without logging user_id.
  let mut act2 = act.unwrap();
  act2.last_verified_at = checked;
  if let Ok(json) = serde_json::to_vec_pretty(&act2) {
    let _ = atomic_write_file(&act_path, &json);
  }

  let st = LicenseStatus {
    state: LicenseState::ProActive,
    license_id: Some(payload.license_id),
    plan: Some(payload.plan),
    seats: Some(payload.seats),
    expires_at_unix_seconds: payload.expires_at,
    last_verified_at_unix_seconds: Some(checked),
    checked_at_unix_seconds: checked,
    reason,
  };
  let _ = write_status(base, &st);
  st
}

fn validate_payload_and_signature(
  payload_bytes: &[u8],
  sig_bytes: &[u8],
) -> anyhow::Result<(LicensePayloadV1, LicenseState, Option<String>)> {
  verify_signature(payload_bytes, sig_bytes)?;
  let payload: LicensePayloadV1 =
    serde_json::from_slice(payload_bytes).context("parse license.json")?;
  let state_reason = validate_fields(&payload);
  Ok((payload, state_reason.0, state_reason.1))
}

fn verify_signature(payload_bytes: &[u8], sig_bytes_raw: &[u8]) -> anyhow::Result<()> {
  let sig_bytes = normalize_sig_bytes(sig_bytes_raw)?;
  if sig_bytes.len() != 64 {
    anyhow::bail!("invalid signature length (expected 64 bytes)");
  }
  let mut sig_arr = [0u8; 64];
  sig_arr.copy_from_slice(&sig_bytes);
  let sig = Signature::from_bytes(&sig_arr);

  let key = verifying_key().context("load embedded public key")?;
  key
    .verify_strict(payload_bytes, &sig)
    .context("signature verification failed")?;
  Ok(())
}

fn normalize_sig_bytes(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
  if raw.len() == 64 {
    return Ok(raw.to_vec());
  }
  // Support base64/base64url text signature files for ease of distribution.
  let text = std::str::from_utf8(raw).context("signature file must be raw bytes or UTF-8")?;
  let t = text.trim();
  if t.is_empty() {
    anyhow::bail!("empty signature");
  }

  URL_SAFE_NO_PAD
    .decode(t.as_bytes())
    .or_else(|_| STANDARD.decode(t.as_bytes()))
    .context("decode signature (base64 or base64url)")
}

fn validate_fields(payload: &LicensePayloadV1) -> (LicenseState, Option<String>) {
  if payload.version != 1 {
    return (LicenseState::ProInvalid, Some("unsupported license version".to_string()));
  }
  if uuid::Uuid::parse_str(payload.license_id.trim()).is_err() {
    return (LicenseState::ProInvalid, Some("license_id must be a UUID".to_string()));
  }
  if payload.plan.trim() != "pro" {
    return (LicenseState::ProInvalid, Some("plan must be \"pro\"".to_string()));
  }
  if payload.seats < 1 {
    return (LicenseState::ProInvalid, Some("seats must be >= 1".to_string()));
  }
  if payload.user_id.trim().is_empty() {
    return (LicenseState::ProInvalid, Some("user_id must be present".to_string()));
  }
  if payload.issued_at == 0 {
    return (LicenseState::ProInvalid, Some("issued_at must be set".to_string()));
  }

  let now = now_unix_s();
  if let Some(exp) = payload.expires_at {
    if exp <= now {
      return (LicenseState::ProExpired, Some("license expired".to_string()));
    }
  }

  (LicenseState::ProActive, None)
}

fn verifying_key() -> anyhow::Result<VerifyingKey> {
  let pk = URL_SAFE_NO_PAD
    .decode(LICENSE_PUBKEY_B64URL.as_bytes())
    .context("decode embedded public key base64url")?;
  if pk.len() != 32 {
    anyhow::bail!("embedded public key must be 32 bytes (ed25519)");
  }
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&pk);
  Ok(VerifyingKey::from_bytes(&arr)?)
}

fn load_license_files(base: &Path) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
  let json_path = paths::license_json_path(base);
  let sig_path = paths::license_sig_path(base);

  let payload_bytes = fs::read(&json_path).with_context(|| format!("read {}", json_path.display()))?;
  let sig_bytes = fs::read(&sig_path).with_context(|| format!("read {}", sig_path.display()))?;

  Ok((payload_bytes, sig_bytes))
}

fn read_activation(path: &Path) -> Option<ActivationState> {
  let bytes = fs::read(path).ok()?;
  serde_json::from_slice(&bytes).ok()
}

fn get_or_create_device_id(base: &Path) -> anyhow::Result<String> {
  let path = paths::device_id_path(base);
  if let Ok(s) = fs::read_to_string(&path) {
    let t = s.trim();
    if uuid::Uuid::parse_str(t).is_ok() {
      return Ok(t.to_string());
    }
  }

  fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
  let id = uuid::Uuid::new_v4().to_string();
  atomic_write_file(&path, id.as_bytes())?;
  Ok(id)
}

fn write_status(base: &Path, st: &LicenseStatus) -> anyhow::Result<()> {
  let dir = paths::license_dir(base);
  fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

  let status_path = paths::license_status_path(base);
  let content = format!(
    "state = \"{}\"\nlicense_id = {}\nplan = {}\nseats = {}\nexpires_at_unix_seconds = {}\nlast_verified_at_unix_seconds = {}\nchecked_at_unix_seconds = {}\nreason = {}\n",
    match st.state {
      LicenseState::Community => "community",
      LicenseState::ProActive => "pro_active",
      LicenseState::ProExpired => "pro_expired",
      LicenseState::ProInvalid => "pro_invalid",
    },
    toml_string_or_null(st.license_id.as_deref()),
    toml_string_or_null(st.plan.as_deref()),
    toml_u32_or_null(st.seats),
    toml_u64_or_null(st.expires_at_unix_seconds),
    toml_u64_or_null(st.last_verified_at_unix_seconds),
    st.checked_at_unix_seconds,
    toml_string_or_null(st.reason.as_deref()),
  );

  atomic_write_file(&status_path, content.as_bytes())?;
  Ok(())
}

fn atomic_write_file(dst: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  let dir = dst.parent().context("destination has no parent directory")?;
  fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

  let tmp = tmp_path(dst);
  fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
  replace_file(&tmp, dst)?;
  Ok(())
}

fn tmp_path(dst: &Path) -> PathBuf {
  let name = dst
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("tmp");
  dst.with_file_name(format!("{name}.new"))
}

fn replace_file(staging: &Path, dst: &Path) -> anyhow::Result<()> {
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
      if bak.exists() {
        let _ = fs::rename(&bak, dst);
      }
      Err(e).with_context(|| format!("replace {}", dst.display()))
    }
  }?;

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

fn toml_u32_or_null(v: Option<u32>) -> String {
  match v {
    Some(x) => x.to_string(),
    None => "null".to_string(),
  }
}

fn now_unix_s() -> u64 {
  now_unix_ms() / 1000
}

#[cfg(test)]
mod tests {
  use super::*;
  use ed25519_dalek::{SigningKey, Signer};

  fn sign(payload: &[u8], key: &SigningKey) -> [u8; 64] {
    let sig: Signature = key.sign(payload);
    sig.to_bytes()
  }

  #[test]
  fn signature_verification_rejects_modified_payload() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();

    // Override embedded key for this test by verifying directly.
    let payload = br#"{"version":1,"license_id":"00000000-0000-0000-0000-000000000000","user_id":"u","plan":"pro","seats":2,"issued_at":1700000000,"expires_at":null,"features":[],"issuer":"x"}"#;
    let sig = sign(payload, &sk);

    let mut tampered = payload.to_vec();
    tampered[10] ^= 1;

    let sig2 = Signature::from_bytes(&sig);
    assert!(vk.verify_strict(payload, &sig2).is_ok());
    assert!(vk.verify_strict(&tampered, &sig2).is_err());
  }

  #[test]
  fn validate_fields_marks_expired() {
    let p = LicensePayloadV1 {
      version: 1,
      license_id: "00000000-0000-0000-0000-000000000000".to_string(),
      user_id: "u".to_string(),
      plan: "pro".to_string(),
      seats: 2,
      issued_at: 1,
      expires_at: Some(1),
      features: vec![],
      issuer: Some("x".to_string()),
    };
    let (st, _) = validate_fields(&p);
    assert_eq!(st, LicenseState::ProExpired);
  }
}

