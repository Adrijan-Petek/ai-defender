# AI Defender Documentation

AI Defender is an early-stage, Windows-first endpoint security engine focused on **behavior-based detection** (for example: sensitive access -> outbound connection). It defaults to **Learning Mode** (monitoring and local logging) to prioritize safety, transparency, and tuning.

This folder contains the project documentation used for development, review, and early-user setup.

## Start here

- Installation and running (developer/early users): `docs/INSTALLATION.md`
- Learning vs Strict mode (safety model): `docs/LEARNING_VS_STRICT.md`
- Threat model (behavior chains, not "AI detection"): `docs/THREAT_MODEL.md`
- Sysmon setup (recommended MVP signal source): `docs/SYSMON.md`
- Scanning (on-demand, early-stage): `docs/SCANNING.md`
- Kill switch recovery (offline-safe): `docs/RECOVERY.md`
- Privacy and logging guarantees: `docs/PRIVACY.md`
- Updates (safe MVP architecture): `docs/UPDATES.md`
- Uninstall notes: `docs/UNINSTALL.md`

## Safety notes

- **Learning Mode** is monitoring-only by default (no automatic containment).
- **Strict Mode** is opt-in and should be enabled only after reviewing logs and tuning allowlists.
- The network kill switch is reversible and crash-safe; auto-triggered locks include a failsafe timer.

