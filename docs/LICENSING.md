# Licensing (user-bound, offline-first)

AI Defender supports an optional “Pro” license while keeping Community mode fully functional offline.

## Principles

- **Offline-first:** Community mode works without any license or server.
- **No telemetry by default:** no data leaves the device unless a user explicitly enables an opt-in feature.
- **Transparent and auditable:** license validation is local signature verification; state is stored on disk.
- **No fingerprinting:** device identity is a random UUID stored locally (no hardware identifiers).

## License token format (v1)

A license consists of two files:

- `license.json` (payload)
- `license.sig` (Ed25519 signature)

The signature is computed over the **exact bytes** of `license.json`.
The agent embeds only the **issuer public key** to verify signatures offline.

Payload fields:

- `version`: `1`
- `license_id`: UUID string
- `user_id`: opaque string (never logged)
- `plan`: `"pro"`
- `seats`: `2`
- `issued_at`: unix seconds
- `expires_at`: unix seconds or `null` (lifetime)
- `features`: string list (e.g., `"threat_feed"`, `"priority_updates"`)
- `issuer`: string identifier (e.g., `"AI Defender License Authority"`)

## Local storage

License files are stored at:

`C:\ProgramData\AI Defender\license\license.json`
`C:\ProgramData\AI Defender\license\license.sig`

The agent also stores local activation state:

`C:\ProgramData\AI Defender\license\activation.json`

And a status file for UI/CLI consumption:

`C:\ProgramData\AI Defender\license\status.toml`

## 2-seat model (server activation planned)

Licenses are intended to be **user-bound** with a **2-seat** concept.

In this phase, there is **no server**, so the agent implements **local-only activation**:

- On first use, the agent generates a stable `device_id` (random UUID) stored at:
  - `C:\ProgramData\AI Defender\device_id.txt`
- Activation writes `activation.json` binding the current `device_id` to the installed `license_id`.

Important limitation:

- The agent does **not** enforce “2 devices total” across machines in offline-only mode.
- A server-backed seat manager may be added later to enforce seats across devices.

## Runtime states

The agent computes and exposes a clear runtime state:

- **Community:** no license installed.
- **ProActive:** valid license + activated on this device.
- **ProExpired:** license expired.
- **ProInvalid:** invalid signature/fields, or valid license but not activated locally.

The agent logs only non-sensitive license details (license ID, plan, expiry) and does not log `user_id`.

## CLI

Examples:

```powershell
agent-core.exe --console --license status
agent-core.exe --console --license install C:\Path\to\license.json C:\Path\to\license.sig
agent-core.exe --console --license activate
agent-core.exe --console --license deactivate
```

## Privacy

- No hardware fingerprinting.
- No telemetry by default.
- No clipboard uploads, file content uploads, or browsing history collection.

See `docs/PRIVACY.md`.

