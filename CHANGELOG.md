# Changelog

All notable changes to this project are documented in this file.

The format follows Keep a Changelog and this project uses semantic versioning pre-1.0 (`0.1.x` alpha).

## [Unreleased]

### Added
- Installer hardening and reproducible MSI build pipeline.
- Threat-feed signed bundle verification and refresh foundations.
- Licensing and tray status integration improvements.

### Changed
- Documentation updates for installation, uninstall, updates, and contributor workflow.

## [0.1.1-alpha] - 2026-02-11

### Added
- Version file and shared product versioning across agent and tray.
- WiX installer authoring updates for ProgramData defaults and cleanup policy.

### Security
- Maintained offline-first defaults and no telemetry by default.

## [0.1.0] - 2026-02-08

### Added
- Initial public alpha baseline:
  - Rust Windows service (`agent-core`)
  - Tray UI
  - Scanner
  - Kill switch, incidents, and rules pipeline
