# Installer (Windows)

AI Defender ships as a per-machine installer for Windows.

## Packaging target

- Product name: `AI Defender`
- Service name: `AI_DEFENDER_AGENT`
- Installer technology: WiX authoring in `installer/wix/AI.Defender.wxs`

## Install behavior

Installer actions:

1. Installs `agent-core.exe`, `scanner.exe`, and `AI.Defender.Tray.exe` to `Program Files\AI Defender`.
2. Registers `AI_DEFENDER_AGENT` as a Windows Service with startup type `Automatic`.
3. Registers tray auto-start at user logon via:
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` -> `AI Defender`
4. Creates ProgramData folders if missing:
   - `C:\ProgramData\AI Defender\`
   - `C:\ProgramData\AI Defender\logs\`
   - `C:\ProgramData\AI Defender\threat-feed\`
   - `C:\ProgramData\AI Defender\license\`
5. Creates default config if missing (`mode = "learning"`).

Safety defaults after install:

- Learning mode remains default.
- Strict mode is not enabled automatically.
- Threat feed auto-refresh remains disabled by default.

## Elevation

Installation is per-machine and requests administrative privileges once through Windows Installer/UAC.

## Build notes

WiX source: `installer/wix/AI.Defender.wxs`.

Single-command local build pipeline:

```powershell
pwsh -File installer/build.ps1
```

Outputs:

- staged payload (`SourceDir`): `installer/build/`
- MSI: `installer/build/AI-Defender-<version>.msi`

WiX requirement:

- Install WiX v4 CLI (`wix`) before running build script.
- Example install: `dotnet tool install --global wix`

This repo keeps installer authoring and build scripts in-source for reviewability and reproducible behavior. Use release CI to sign produced MSI packages.
