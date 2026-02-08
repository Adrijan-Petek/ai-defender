# Installer (WiX)

Installer scaffolding for AI Defender.

This folder contains a WiX authoring baseline to install:

- `agent-core.exe` as the Windows Service `AI_DEFENDER_AGENT`
- `AI.Defender.Tray.exe` per-user tray UI
- `scanner.exe` on-demand scanner
- HKCU autostart for the tray UI

Uninstall should remove:

- the service
- AI Defender kill switch firewall rules
- installed binaries
- ProgramData state (optional: prompt user)

See `docs/INSTALLATION.md` and `docs/UNINSTALL.md`.

