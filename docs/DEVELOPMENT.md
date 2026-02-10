# Development

This guide is for contributors working on the Rust agent (`agent-core`), Rust scanner, and the Windows tray UI.

## Prerequisites

- Windows 11 (recommended for end-to-end runs)
- Rust stable toolchain (`rustup`)
- .NET SDK 8.x

## Build (Rust)

From the repo root:

```powershell
cargo build -p agent-core
cargo build -p scanner
```

Run tests:

```powershell
cargo test -p agent-core
```

Format and lint:

```powershell
cargo fmt --all
cargo clippy -p agent-core -p scanner -- -D warnings
```

## Build (Tray UI)

```powershell
dotnet build ui/AI.Defender.Tray/AI.Defender.Tray.csproj -c Release
```

## Agent console / CLI usage (MVP)

`agent-core` supports a local “console mode” intended for recovery and development:

```powershell
# Kill switch (manual)
agent-core.exe --console --killswitch on
agent-core.exe --console --killswitch off
agent-core.exe --console --killswitch status

# Incident listing (text)
agent-core.exe --console --incidents list --limit 10
```

## File locations (Windows)

AI Defender stores configuration and state under ProgramData:

- Config: `C:\ProgramData\AI Defender\config.toml`
- Logs: `C:\ProgramData\AI Defender\logs\`
- Kill switch state: `C:\ProgramData\AI Defender\killswitch-state.toml`
- Incidents: `C:\ProgramData\AI Defender\incidents\`

## Testing without Sysmon (simulation mode)

Simulation is designed for deterministic development and CI-like checks without Sysmon.

```powershell
# Simulate a RED chain (sensitive access -> net connect)
agent-core.exe --console --simulate red

# Simulate individual event types
agent-core.exe --console --simulate file-access-chrome
agent-core.exe --console --simulate net-connect
agent-core.exe --console --simulate chain-red
```

Notes:
- Simulation does not require Sysmon.
- Simulation may require Administrator privileges if it triggers the kill switch in strict mode with auto-trigger enabled.

## Debugging checklist

- Confirm service status in `services.msc` (service name comes from `PRODUCT.toml` / defaults).
- Check `C:\ProgramData\AI Defender\logs\` for agent logs.
- If networking is locked, follow `docs/RECOVERY.md` and disable the kill switch.
- If rules do not load in strict mode, the agent may refuse strict mode when no active rules are available.

