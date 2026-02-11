# Threat Feed Auto Refresh (Pro, opt-in)

AI Defender supports optional automatic threat feed refresh for Pro licenses.
This feature is disabled by default and must be explicitly enabled in config.

## Safety model

- Community mode never fetches updates.
- Pro mode still does not fetch unless `threat_feed.auto_refresh = true`.
- No telemetry and no data upload in this flow.
- Downloads are only `bundle.json` and `bundle.sig`.
- Signature and schema verification happen before install.
- If refresh fails, AI Defender keeps the current/last-known-good bundle.

## Config

```toml
[threat_feed]
auto_refresh = false
refresh_interval_minutes = 60
endpoints = ["https://updates.aidefender.shop/feed/"]
allowlist_domains = ["updates.aidefender.shop"]
timeout_seconds = 10
```

Validation rules:

- Endpoint must be HTTPS.
- Endpoint host must exactly match `allowlist_domains`.
- Invalid config disables auto-refresh and logs a calm warning.

## Network behavior

When eligible and due, the agent requests:

- `GET {endpoint}/bundle.json`
- `GET {endpoint}/bundle.sig`

Security controls:

- Redirects disabled.
- Request timeout from config.
- User-Agent is `AI-Defender/<version>`.
- Max sizes: `bundle.json` 2 MB, `bundle.sig` 8 KB.
- No device IDs, license keys, or auth headers are sent.

## Eligibility

Auto refresh only runs when both are true:

1. `threat_feed.auto_refresh = true`
2. License status is `ProActive`

If not eligible, no network fetch occurs.

## Status and CLI

Status includes:

- Current bundle `rules_version`
- `created_at`
- `last_verified_at`
- `last_refresh_attempt_at`
- `last_refresh_result`

CLI:

```powershell
agent-core.exe --console --feed auto-refresh status
agent-core.exe --console --feed refresh-now
```

`refresh-now` performs one eligible attempt. If not eligible, it prints a clear reason and does nothing.

## Offline fallback

For fully offline use, import bundles manually:

```powershell
agent-core.exe --console --feed import C:\path\bundle.json C:\path\bundle.sig
```

This remains the primary fallback if network access is unavailable.
