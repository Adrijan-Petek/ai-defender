# AI Defender
![CI](https://github.com/Adrijan-Petek/ai-defender/actions/workflows/ci.yml/badge.svg)

<p align="center">
  <img src="assets/ai-defender.png" alt="AI Defender logo" width="120" />
</p>

Behavior-based Windows security (early-stage, learning mode by default)

## What AI Defender is

AI Defender is an **endpoint security engine** for Windows, focused on **behavior-based detection** to help defend against:

- silent data theft
- wallet drains
- automation-based malware

AI Defender does **not** "detect AI". It detects **behavior chains** (for example: sensitive access -> outbound connection) that theft-focused malware cannot avoid.

## What it currently does

- Runs as a Windows Service (`AI_DEFENDER_AGENT`) using stable Rust.
- Observes system behavior signals (process, file, and network events; Windows-first).
- Correlates sensitive access patterns into incidents (learning-first).
- Logs incidents locally and stores incident records under ProgramData.
- Provides a **manual + automatic network kill switch** (Windows Firewall).
- Includes a tray UI for visibility and user-controlled actions.
- Includes a local on-demand scanner (early-stage).

## What it does not do (yet)

- No kernel drivers.
- No silent blocking by default (Learning mode is monitoring-only).
- No cloud dependency required for core functionality.
- No telemetry without explicit consent.
- No guaranteed "complete protection".
- No "AI detection" claims or AI spying.

## Learning mode vs strict mode

Learning Mode (default):

- Monitoring only.
- Logs findings and stores incidents locally.
- Does **not** auto-block or auto-contain.

Strict Mode (opt-in):

- Enables automatic responses for **high-confidence RED incidents** (behavior chains).
- Can auto-trigger the network kill switch if configured.

Learning mode is the default and recommended starting point.

## Kill switch (important)

AI Defender includes an emergency network kill switch that:

- Blocks **all inbound + outbound** traffic using Windows Firewall.
- Can be triggered manually (panic action).
- Can be triggered automatically in **Strict Mode** for RED incidents only (behavior-chain containment).
- Uses a failsafe auto-restore timer for auto-triggered locks.
- Is reversible and crash-safe (state is persisted; recovery is documented).

Recovery instructions: see `docs/RECOVERY.md`.

## Project structure

- `agent-core/` — Rust Windows service, detection pipeline, incidents, kill switch, console/dev tools
- `rules-engine/` — reserved for future external rule formats; current MVP rules live in `agent-core/`
- `scanner/` — on-demand scanner (early-stage; reports findings as local incidents)
- `ui/` — Windows tray UI (status + user confirmations + scan UI)
- `docs/` — threat model, learning vs strict, Sysmon notes, recovery, install/uninstall, privacy
- `assets/` — branding (logo)

## Installation (developer / early users)

AI Defender is early-stage. There is **no polished installer release yet** (an installer scaffold exists under `installer/`).

### Prerequisites

- Windows 10/11
- Rust toolchain (stable) for building the agent/scanner
- .NET SDK (Windows) for building the tray UI

### Build

- Build agent: `cargo build -p agent-core`
- Build scanner: `cargo build -p scanner`
- Run agent console/dev mode: `cargo run -p agent-core -- --console --help`
- Build tray UI: open `ui/AI.Defender.Tray/AI.Defender.Tray.csproj` in Visual Studio and build (or use `dotnet build` on Windows)

### Run (dev / recovery)

- Console commands (examples):
  - `cargo run -p agent-core -- --console --killswitch status`
  - `cargo run -p agent-core -- --console --incidents list --limit 10`
  - `cargo run -p agent-core -- --console --simulate chain-red`

### Admin privileges

- Installing/running the Windows Service requires Administrator privileges.
- Modifying Windows Firewall rules (kill switch) typically requires Administrator privileges.

## Security & privacy

- No data exfiltration by default.
- No hidden telemetry.
- Logs and incident records are local (`C:\ProgramData\AI Defender\`).
- Clipboard contents and file contents are **not** stored.
- Designed to be auditable and conservative by default.

Security reporting: see `SECURITY.md`.

## Project status & roadmap

Status:

- Early-stage / experimental
- Not production-ready yet
- Learning-first, monitoring by default

Roadmap (high level):

- Detection hardening and false-positive reduction
- UI polish and UX review
- Installer hardening and signing
- Optional paid threat feeds (opt-in and transparent; not required for core operation)

## Contributing

Contributions are welcome, especially around safety, auditability, and false-positive reduction.

- Defensive-only project: do not propose offensive capabilities or bypasses.
- See `CONTRIBUTING.md`.

## Disclaimer

AI Defender is security software in active development. Use at your own risk.

It is not a replacement for a mature enterprise EDR product (yet).
