# Updates (Threat Feed)

AI Defender does not silently self-update its binaries.

Only signed threat-feed bundles are refreshed, and only under explicit conditions.

## Default endpoint readiness

Default threat-feed endpoint:

- `https://updates.aidefender.shop/feed/`

Strict controls:

- HTTPS required
- Exact host allowlist match (`updates.aidefender.shop`)
- Redirects disabled
- Size limits:
  - `bundle.json` <= 2 MB
  - `bundle.sig` <= 8 KB

## Eligibility and opt-in

Auto-refresh runs only when all are true:

1. License status is `ProActive`
2. `threat_feed.auto_refresh = true`
3. Threat-feed config passes validation

Community mode never fetches threat-feed updates.

## Privacy model

Threat-feed refresh downloads only:

- `bundle.json`
- `bundle.sig`

It does not send:

- license key
- device identifier
- incident data
- telemetry payloads

## Verification and install policy

Downloaded bundles must pass:

- Ed25519 signature verification
- schema validation
- version compatibility checks

Install is atomic. If any step fails:

- current bundle remains in place
- last-known-good remains available
- refresh failure is logged with a short reason

## Offline operation

Manual import remains available and supported:

```powershell
agent-core.exe --console --feed import C:\path\bundle.json C:\path\bundle.sig
```

This guarantees offline usability even when update endpoints are unavailable.
