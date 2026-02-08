# AI Defender Tray UI

Per-user Windows tray application for AI Defender.

## What it does (v1)

- Shows protection status (learning/strict, agent running, network locked).
- Provides explicit, user-confirmed controls:
  - Enable kill switch NOW
  - Restore network
  - Toggle learning/strict mode (writes config; restart required)
- Displays a calm “Last Incident” dialog (no secrets).
- Opens the local logs folder.

Exiting the UI does **not** stop the agent service.

## How the UI talks to the agent

MVP communication is local-only CLI invocation:

- The tray app runs `agent-core.exe --console ...` for kill switch actions.
- It reads real state from local files under ProgramData (config/state/incidents) to avoid guessing.
- It runs `scanner.exe` for on-demand scans (results are stored as incidents).

No network communication is performed by the UI.

### Agent executable discovery (MVP)

The UI looks for `agent-core.exe`:

1) Next to the tray UI executable (recommended for MVP packaging)
2) A dev fallback relative path under `target\\release\\agent-core.exe` (when running from repo output)

## Logo integration

- Source logo: `assets/ai-defender.png`
- The tray app embeds the PNG as an assembly resource.
- It uses the logo for:
  - Tray icon
  - Dialog/window icon

Tray “state” is represented by a small badge dot drawn in the icon corner (logo artwork is not altered).

## Recovery if UI fails (network locked)

Preferred (uses agent):

- `cargo run -p agent-core -- --console --killswitch off`

Emergency (no agent required, run as Administrator):

- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Outbound" group="AI_DEFENDER_KILLSWITCH"`
- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Inbound" group="AI_DEFENDER_KILLSWITCH"`

## File locations (Windows)

- Config: `C:\\ProgramData\\AI Defender\\config.toml`
- Logs: `C:\\ProgramData\\AI Defender\\logs\\`
- Kill switch state: `C:\\ProgramData\\AI Defender\\killswitch-state.toml`
- Incidents: `C:\\ProgramData\\AI Defender\\incidents\\`

## Version identity

The tray UI uses `PRODUCT.toml` (copied next to the UI exe) as the single source of product name/service/version and warns if the agent version differs.
