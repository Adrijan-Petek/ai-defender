# Pro Mode

AI Defender is offline-first in both Community and Pro modes.

## Community mode

Community behavior is conservative by default:

- Learning mode default
- No auto-response behavior from strict-mode policies
- No threat-feed auto-refresh
- Manual kill switch remains available
- No telemetry by default

## Pro mode

Pro mode adds access to signed threat-feed usage and optional automation controls:

- Signed threat-feed bundle support (same verification model)
- Auto-refresh can be enabled by user (still disabled by default)
- Strict mode can be user-enabled for automated response policies
- No telemetry by default

## Important boundaries

- Pro mode does not bypass safety checks.
- Pro mode does not enable silent agent self-updates.
- Pro mode does not upload incidents or user data by default.

## UI expectations

Tray UI displays:

- Community vs Pro state
- License expiry (when present)
- Current operating mode (Learning/Strict)
- Kill switch status
- Threat-feed status
