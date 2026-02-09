# AI Defender Tray UI

Per-user Windows tray application for AI Defender.

## What it does (v1)

- Shows protection status (agent running, learning/strict, kill switch state).
- Provides explicit, user-confirmed controls:
  - Enable Kill Switch NOW
  - Restore Network
  - Toggle Learning / Strict Mode (writes config; restart required)
- Displays a minimal “Last Incident” dialog (no raw logs, no sensitive data).
- Opens the local logs folder.

Exiting the UI does **not** stop the agent service.

## How the UI talks to the agent

MVP communication is local-only CLI invocation plus agent-owned state files:

- The tray app runs `agent-core.exe --console ...` for kill switch actions.
- It reads real state from local files under ProgramData (config/state/incidents) to avoid guessing.

No network communication is performed by the UI.

### Agent executable discovery (MVP)

The UI looks for `agent-core.exe`:

1) Next to the tray UI executable (recommended for MVP packaging)
2) A dev fallback relative path under `target\release\agent-core.exe` (when running from repo output)

## File locations (Windows)

- Config: `C:\ProgramData\AI Defender\config.toml`
- Logs: `C:\ProgramData\AI Defender\logs\`
- Kill switch state: `C:\ProgramData\AI Defender\killswitch-state.toml`
- Incidents: `C:\ProgramData\AI Defender\incidents\`

## Recovery if UI fails (network locked)

Preferred (uses agent):

- `cargo run -p agent-core -- --console --killswitch off`

Emergency (no agent required, run as Administrator):

- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Outbound" group="AI_DEFENDER_KILLSWITCH"`
- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Inbound" group="AI_DEFENDER_KILLSWITCH"`
