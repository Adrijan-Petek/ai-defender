# Privacy

AI Defender is designed to be transparent and offline-first.

## No hidden telemetry (default)

- AI Defender does not send data to any cloud service by default.
- The tray UI does not make network connections.
- The agent does not make outbound network calls by default.

## Logging rules

- AI Defender logs actions and incidents locally for auditability.
- AI Defender does not log:
  - clipboard contents
  - file contents
  - passwords, seeds, or private keys

## Local storage

AI Defender stores only local operational files under `C:\ProgramData\AI Defender\`:

- configuration
- logs
- incident records
- kill switch state

## Optional paid mode (updates only, opt-in)

AI Defender may support an optional paid protection layer in the future. If enabled, paid mode may contact **only update endpoints** to download signed rule bundles.

Principles:

- Opt-in only (disabled by default)
- No incident upload required for basic updates
- All update activity should be logged locally
- Signed bundles are verified locally before use

What paid mode still does not do:

- No keylogging
- No clipboard uploads
- No file content uploads
- No browsing history collection
- No hidden telemetry

