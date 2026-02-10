# Paid protection (optional)

AI Defender uses an “open-core + optional paid services” model.

- The open-source agent remains fully functional offline.
- There is no telemetry or data upload by default.
- Paid features are opt-in and documented.
- This repo does not implement payments or billing.

## What paid protection may provide

Paid users may optionally enable:

- **Signed rule updates (threat feed):** a vendor-signed bundle of rule metadata and reputation lists.
- **Faster refresh cadence:** more frequent delivery of signed updates (delivery automation is out of scope in code for this phase).
- **Reputation list updates:** curated lists that support detections (e.g., known-drainer domains, hashes, wallet-drain patterns).
- **Priority support:** process and SLAs (out of scope in code).

In v1, the paid layer is designed as an *offline-capable update mechanism*. Users can import signed bundles locally without any network access.

## What paid protection does NOT do

Paid protection does not change AI Defender into spyware and does not introduce hidden data collection. Specifically:

- No keylogging
- No clipboard uploads
- No file content uploads
- No browsing history collection
- No hidden telemetry

## License model (local, offline)

AI Defender supports a local license file stored at:

`C:\ProgramData\AI Defender\license\license.json`
`C:\ProgramData\AI Defender\license\license.sig`

The license format is a signed token:

- Base64url JSON payload + signature (public-key verification)
- Verified locally using an embedded public key
- No secrets are embedded in the code

The signature is computed over the exact bytes of `license.json`. The agent validates it offline using an embedded public key.

The JSON payload contains conservative fields such as:

```json
{
  "license_id": "LIC-EXAMPLE-001",
  "plan": "pro",
  "issued_at": 1700000000,
  "expires_at": 1730000000,
  "seats": 2,
  "features": ["threat_feed", "priority_updates"],
  "issuer": "AI Defender License Authority",
  "user_id": "opaque"
}
```

If no valid license is installed, the agent runs in **Community** mode.
If a valid license is installed, the agent reports **Pro** mode.

## Threat feed bundles (signed, offline import)

Threat feed bundles are versioned files stored at:

`C:\ProgramData\AI Defender\threat-feed\bundle.json`
`C:\ProgramData\AI Defender\threat-feed\bundle.sig`

The agent verifies:

- the signature is valid (embedded public key)
- the bundle version is newer than the currently installed bundle
- the bundle schema is correct

If a bundle is invalid, the agent ignores it and keeps the last known good bundle.

Bundle schema (v1, JSON) is intentionally non-executable and conservative:

- `version` (monotonically increasing integer)
- `created_at_unix_ms`
- `issuer` (optional)
- `notes` (optional)
- `reputation` (optional lists such as domains/hashes/patterns)

## Network behavior and privacy

By default:

- AI Defender does not contact any update endpoints.
- AI Defender does not upload incidents or sensitive data.

If a paid update mechanism is enabled in the future, it will:

- be opt-in
- be documented
- use only update endpoints (no data upload required for basic updates)
- log update activity locally for auditability

See `docs/PRIVACY.md`.
