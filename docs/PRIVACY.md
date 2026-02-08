# Privacy

AI Defender is designed to be transparent and offline-first.

## No hidden telemetry (default)

- AI Defender does not send data to any cloud service by default.
- The tray UI does not make network connections.

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

