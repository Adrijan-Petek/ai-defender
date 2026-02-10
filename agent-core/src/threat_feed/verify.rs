use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

// Public-key only. Replace with the production public key for threat feed verification.
const FEED_PUBKEY_B64URL: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub fn verify_bundle_signature(bundle_json: &[u8], sig_bytes: &[u8]) -> anyhow::Result<()> {
  if sig_bytes.len() != 64 {
    anyhow::bail!("invalid signature length (expected 64 bytes)");
  }
  let mut sig_arr = [0u8; 64];
  sig_arr.copy_from_slice(sig_bytes);
  let sig = Signature::from_bytes(&sig_arr);

  let key = verifying_key().context("load embedded public key")?;
  key
    .verify_strict(bundle_json, &sig)
    .context("signature verification failed")?;
  Ok(())
}

pub fn decode_sig_base64url(text: &str) -> anyhow::Result<Vec<u8>> {
  URL_SAFE_NO_PAD
    .decode(text.trim().as_bytes())
    .context("decode signature base64url")
}

fn verifying_key() -> anyhow::Result<VerifyingKey> {
  let pk = URL_SAFE_NO_PAD
    .decode(FEED_PUBKEY_B64URL.as_bytes())
    .context("decode embedded public key base64url")?;
  if pk.len() != 32 {
    anyhow::bail!("embedded public key must be 32 bytes (ed25519)");
  }
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&pk);
  Ok(VerifyingKey::from_bytes(&arr)?)
}

