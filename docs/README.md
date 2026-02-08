# AI Defender (MVP docs)

See also:

- `docs/THREAT_MODEL.md`
- `docs/LEARNING_VS_STRICT.md`
- `docs/SYSMON.md`
- `docs/RECOVERY.md`
- `docs/INSTALLATION.md`
- `docs/SCANNING.md`
- `docs/PRIVACY.md`
- `docs/UNINSTALL.md`
- `docs/UPDATES.md`

## What the kill switch does

AI Defender's kill switch is a defensive "network lock":

- Adds two Windows Firewall rules in the dedicated group `AI_DEFENDER_KILLSWITCH`
  - Block Outbound: any program, any protocol, all profiles
  - Block Inbound: any program, any protocol, all profiles
- When enabled, it blocks all inbound + outbound traffic (system-wide).
- When disabled, it removes only AI Defender's two rules and restores networking.

Implementation note:

- Primary: Windows Firewall COM API (INetFwPolicy2/INetFwRule).
- Fallback: a minimal `netsh` path is used only if COM is unavailable.

## Manual vs auto-trigger behavior

- Manual (`--killswitch on`):
  - Locks the network immediately.
  - Never auto-restores.
- Auto-trigger (RED-only):
  - Triggers only on RED incidents and only if `killswitch.auto_trigger = true`.
  - Starts a failsafe timer (`failsafe_minutes`, default 10) that restores network access unless `keep_locked = true`.

## Recovery if UI fails / network is locked

Preferred (uses the agent):

- `cargo run -p agent-core -- --console --killswitch off`

Emergency (no agent required, run as Administrator):

- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Outbound" group="AI_DEFENDER_KILLSWITCH"`
- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Inbound" group="AI_DEFENDER_KILLSWITCH"`

These emergency commands remove only AI Defender's kill switch rules.

## Files and locations (Windows)

- Config: `C:\ProgramData\AI Defender\config.toml`
- Logs: `C:\ProgramData\AI Defender\logs\agent-core.log.YYYY-MM-DD`
- Kill switch state: `C:\ProgramData\AI Defender\killswitch-state.toml`
- Incidents: `C:\ProgramData\AI Defender\incidents\{incident_id}.toml`

## Console commands

- `--killswitch on|off|status`
- `--killswitch keep-locked true|false`
- `--simulate red`

## Safety notes

- No kernel drivers in v1.
- No hidden telemetry or outbound network calls in core logic.
- Kill switch operations only touch the rule group `AI_DEFENDER_KILLSWITCH` and only the two known rule names.
