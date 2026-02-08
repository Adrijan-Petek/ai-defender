# Installation (MVP)

AI Defender has two components:

- `AI_DEFENDER_AGENT` (Windows Service) — core protection engine
- Tray UI (per-user) — status + manual controls + scans

## Installer

The repository includes WiX authoring scaffolding in `installer/wix/AI.Defender.wxs`.

Expected installer responsibilities:

- Install `agent-core.exe` and register it as the Windows service `AI_DEFENDER_AGENT`
- Install `AI.Defender.Tray.exe`
- Install `scanner.exe`
- Register tray UI autostart (HKCU Run)
- Uninstall cleanup removes AI Defender firewall kill switch rules

## Manual dev install (no MSI)

1) Build binaries:
   - `agent-core.exe` (service host + console commands)
   - `AI.Defender.Tray.exe` (tray UI)
   - `scanner.exe` (on-demand scanner)
2) Place binaries into an install folder (e.g., `C:\Program Files\AI Defender\`).
3) Register and start service (Administrator):
   - `sc create AI_DEFENDER_AGENT binPath= "C:\Program Files\AI Defender\agent-core.exe" start= auto`
   - `sc start AI_DEFENDER_AGENT`
4) Run tray UI as the user.

## Where AI Defender stores files

- `C:\ProgramData\AI Defender\config.toml`
- `C:\ProgramData\AI Defender\logs\`
- `C:\ProgramData\AI Defender\killswitch-state.toml`
- `C:\ProgramData\AI Defender\incidents\`

