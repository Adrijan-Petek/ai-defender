use crate::config::ThreatFeedConfig;
use anyhow::Context;
use reqwest::blocking::{Client, Response};
use reqwest::header::USER_AGENT;
use reqwest::redirect::Policy;
use reqwest::Url;
use std::io::Read;
use std::time::Duration;

const MAX_BUNDLE_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_SIG_BYTES: usize = 8 * 1024;

pub struct FetchedBundle {
  pub bundle_json: Vec<u8>,
  pub bundle_sig: Vec<u8>,
  pub host: String,
}

pub fn validate_refresh_config(cfg: &ThreatFeedConfig) -> anyhow::Result<()> {
  if cfg.refresh_interval_minutes == 0 {
    anyhow::bail!("refresh_interval_minutes must be > 0");
  }
  if cfg.timeout_seconds == 0 {
    anyhow::bail!("timeout_seconds must be > 0");
  }
  if cfg.endpoints.is_empty() {
    anyhow::bail!("endpoints must not be empty");
  }
  if cfg.allowlist_domains.is_empty() {
    anyhow::bail!("allowlist_domains must not be empty");
  }

  for endpoint in &cfg.endpoints {
    let url = Url::parse(endpoint).with_context(|| format!("invalid endpoint: {endpoint}"))?;
    validate_endpoint(&url, &cfg.allowlist_domains)?;
  }

  Ok(())
}

pub fn fetch_bundle(cfg: &ThreatFeedConfig) -> anyhow::Result<FetchedBundle> {
  validate_refresh_config(cfg)?;

  let endpoint = choose_endpoint(cfg)?;
  let host = endpoint
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("endpoint host missing"))?
    .to_string();

  let client = Client::builder()
    .timeout(Duration::from_secs(cfg.timeout_seconds))
    .redirect(Policy::none())
    .build()
    .context("build HTTP client")?;

  let bundle_url = endpoint
    .join("bundle.json")
    .with_context(|| format!("build bundle URL from endpoint {endpoint}"))?;
  validate_endpoint(&bundle_url, &cfg.allowlist_domains)?;

  let sig_url = endpoint
    .join("bundle.sig")
    .with_context(|| format!("build signature URL from endpoint {endpoint}"))?;
  validate_endpoint(&sig_url, &cfg.allowlist_domains)?;

  let bundle_json = http_get_bytes(&client, &bundle_url, MAX_BUNDLE_JSON_BYTES)?;
  let bundle_sig = http_get_bytes(&client, &sig_url, MAX_BUNDLE_SIG_BYTES)?;

  Ok(FetchedBundle {
    bundle_json,
    bundle_sig,
    host,
  })
}

fn choose_endpoint(cfg: &ThreatFeedConfig) -> anyhow::Result<Url> {
  for raw in &cfg.endpoints {
    let Ok(url) = Url::parse(raw) else {
      continue;
    };
    if validate_endpoint(&url, &cfg.allowlist_domains).is_ok() {
      return Ok(url);
    }
  }

  anyhow::bail!("no valid threat feed endpoint available")
}

fn validate_endpoint(url: &Url, allowlist_domains: &[String]) -> anyhow::Result<()> {
  if url.scheme() != "https" {
    anyhow::bail!("endpoint must use HTTPS");
  }

  let host = url
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("endpoint host missing"))?;
  if !allowlist_domains.iter().any(|d| d == host) {
    anyhow::bail!("endpoint host not in allowlist");
  }

  Ok(())
}

fn http_get_bytes(client: &Client, url: &Url, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
  let response = client
    .get(url.clone())
    .header(
      USER_AGENT,
      format!("AI-Defender/{}", env!("CARGO_PKG_VERSION")),
    )
    .send()
    .with_context(|| format!("GET {}", safe_url_label(url)))?;

  if response.status().as_u16() != 200 {
    anyhow::bail!(
      "unexpected HTTP status {} for {}",
      response.status().as_u16(),
      safe_url_label(url)
    );
  }

  read_response_with_limit(response, max_bytes)
}

fn read_response_with_limit(mut response: Response, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
  let mut out = Vec::new();
  let mut limited = response.take((max_bytes.saturating_add(1)) as u64);
  limited
    .read_to_end(&mut out)
    .context("read response body")?;

  if out.len() > max_bytes {
    anyhow::bail!("response exceeds max size {} bytes", max_bytes);
  }

  Ok(out)
}

fn safe_url_label(url: &Url) -> String {
  let host = url.host_str().unwrap_or("<no-host>");
  let mut path = url.path().to_string();
  if path.is_empty() {
    path = "/".to_string();
  }
  format!("{host}{path}")
}
