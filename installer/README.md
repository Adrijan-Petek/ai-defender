# Installer (WiX)

Installer authoring for AI Defender (WiX).

This folder contains WiX authoring to install:

- `agent-core.exe` as the Windows Service `AI_DEFENDER_AGENT`
- `AI.Defender.Tray.exe` tray UI
- `scanner.exe` on-demand scanner
- HKLM autostart for the tray UI at user logon

Uninstall removes:

- the service
- AI Defender kill switch firewall rules by group (`AI_DEFENDER_KILLSWITCH`)
- installed binaries
- ProgramData state optionally (`REMOVE_PROGRAMDATA=1`)

See `docs/INSTALLER.md` and `docs/UNINSTALL.md`.

## Reproducible build pipeline

Use a single script to build payload + MSI:

```powershell
pwsh -File installer/build.ps1
```

This script:

1. Builds Rust binaries (`agent-core.exe`, `scanner.exe`)
2. Publishes tray UI (`AI.Defender.Tray.exe`) with:
   - `dotnet publish ... -r win-x64 --self-contained false`
3. Copies payload to `installer/build/` (`SourceDir`)
4. Builds MSI to `installer/build/AI-Defender-<version>.msi`

Required tools:

- Rust (`cargo`)
- .NET SDK
- WiX v4 CLI (`wix`)

## ProgramData uninstall option

Default uninstall keeps ProgramData (recommended).

Optional full removal:

```powershell
msiexec /x {PRODUCT-CODE} REMOVE_PROGRAMDATA=1
```
