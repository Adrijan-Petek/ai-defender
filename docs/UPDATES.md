# Updates (safe MVP architecture)

AI Defender must never update itself silently.

## Principles

- The agent (`AI_DEFENDER_AGENT`) does **not** auto-update itself.
- Updates require explicit user approval.
- Update packages must be signed and verifiable offline.
- Network access is optional and user-initiated (e.g., “Check for updates”).

## Suggested MVP design (no implementation yet)

1) **Separate updater component** (runs per-user from the tray UI).
2) Updater downloads an update package only after user confirms.
3) Package format:
   - includes `agent-core.exe`, `scanner.exe`, `AI.Defender.Tray.exe`, `PRODUCT.toml`
   - includes a signed manifest (publisher cert)
4) Validation:
   - verify signature before applying
   - verify version monotonicity (no downgrade without explicit override)
5) Apply:
   - stop service
   - replace binaries atomically
   - start service

If validation fails, nothing is applied and the user is shown a clear error.

