use crate::paths;
use crate::types::now_unix_ms;
use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// Public-key only. Replace with the production public key for license verification.
//
// This placeholder key verifies tokens signed by the corresponding private key.
// It should be rotated/replaced for real deployments.
const LICENSE_PUBKEY_B64URL: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
  pub license_id: String,
  pub plan: String,
  pub issued_at_unix_ms: u64,

  #[serde(default)]
  pub expires_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseFile {
  pub token: String,
}

#[derive(Debug, Clone)]
pub struct LicenseStatus {
  pub pro: bool,
  pub license_id: Option<String>,
  pub plan: Option<String>,
  pub expires_at_unix_ms: Option<u64>,
  pub checked_at_unix_ms: u64,
  pub reason: Option<String>,
}

impl LicenseStatus {
  pub fn community(reason: Option<String>) -> Self {
    Self {
      pro: false,
      license_id: None,
      plan: None,
      expires_at_unix_ms: None,
      checked_at_unix_ms: now_unix_ms(),
      reason,
    }
  }

  pub fn pro(claims: &LicenseClaims) -> Self {
    Self {
      pro: true,
      license_id: Some(claims.license_id.clone()),
      plan: Some(claims.plan.clone()),
      expires_at_unix_ms: claims.expires_at_unix_ms,
      checked_at_unix_ms: now_unix_ms(),
      reason: None,
    }
  }
}

pub fn status(base: &Path) -> LicenseStatus {
  let path = paths::license_path(base);
  let Some(tok) = read_token(&path) else {
    let st = LicenseStatus::community(Some("no license installed".to_string()));
    let _ = write_state(base, &st);
    return st;
  };

  match validate_token(&tok) {
    Ok(claims) => {
      let st = LicenseStatus::pro(&claims);
      let _ = write_state(base, &st);
      st
    }
    Err(e) => {
      let st = LicenseStatus::community(Some(format!("invalid license: {e:#}")));
      let _ = write_state(base, &st);
      st
    }
  }
}

pub fn install(base: &Path, src_path: &Path) -> anyhow::Result<LicenseStatus> {
  let src = fs::read_to_string(src_path)
    .with_context(|| format!("read license file {}", src_path.display()))?;

  let lf: LicenseFile = toml::from_str(&src).context("parse license TOML")?;
  let claims = validate_token(&lf.token).context("validate license token")?;

  fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
  let dst = paths::license_path(base);
  fs::write(&dst, src).with_context(|| format!("write {}", dst.display()))?;

  let st = LicenseStatus::pro(&claims);
  write_state(base, &st)?;
  Ok(st)
}

pub fn validate_token(token: &str) -> anyhow::Result<LicenseClaims> {
  // Token format: base64url(payload_json) + "." + base64url(signature)
  let parts: Vec<&str> = token.trim().split('.').collect();
  if parts.len() != 2 {
    anyhow::bail!("expected token format payload_b64url.signature_b64url");
  }

  let payload_b64 = parts[0];
  let sig_b64 = parts[1];

  let payload = URL_SAFE_NO_PAD
    .decode(payload_b64.as_bytes())
    .context("decode payload base64url")?;
  let sig_bytes = URL_SAFE_NO_PAD
    .decode(sig_b64.as_bytes())
    .context("decode signature base64url")?;

  if sig_bytes.len() != 64 {
    anyhow::bail!("invalid signature length (expected 64 bytes)");
  }
  let mut sig_arr = [0u8; 64];
  sig_arr.copy_from_slice(&sig_bytes);
  let sig = Signature::from_bytes(&sig_arr);

  let key = verifying_key().context("load embedded public key")?;
  key
    .verify_strict(&payload, &sig)
    .context("signature verification failed")?;

  let claims: LicenseClaims =
    serde_json::from_slice(&payload).context("parse license claims JSON")?;

  let now = now_unix_ms();
  if let Some(exp) = claims.expires_at_unix_ms {
    if exp <= now {
      anyhow::bail!("license expired");
    }
  }

  if claims.plan.trim().is_empty() || claims.license_id.trim().is_empty() {
    anyhow::bail!("missing required claims");
  }

  Ok(claims)
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

fn read_token(path: &PathBuf) -> Option<String> {
  let text = fs::read_to_string(path).ok()?;
  let lf: LicenseFile = toml::from_str(&text).ok()?;
  if lf.token.trim().is_empty() {
    return None;
  }
  Some(lf.token.trim().to_string())
}

fn write_state(base: &Path, st: &LicenseStatus) -> anyhow::Result<()> {
  fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
  let path = paths::license_state_path(base);

  let content = format!(
    "pro = {}\nlicense_id = {}\nplan = {}\nexpires_at_unix_ms = {}\nchecked_at_unix_ms = {}\nreason = {}\n",
    st.pro,
    toml_string_or_null(st.license_id.as_deref()),
    toml_string_or_null(st.plan.as_deref()),
    toml_u64_or_null(st.expires_at_unix_ms),
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
