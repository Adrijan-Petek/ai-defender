# Roadmap (conservative)

This roadmap is intentionally conservative. The goal is a reliable, reviewable defensive tool with safe defaults.

## Option 1 — User polish (UI + installer)

Focus: reduce friction for early users.

- Tray UX: clearer status, fewer surprises, solid recovery guidance
- Installer: reliable service install/uninstall, versioning, upgrades
- Documentation surfaced in-product (links, status details)

## Option 2 — Docs and tests (this phase)

Focus: reviewability and contributor experience.

- Architecture and threat model docs
- Rule documentation and rationale
- Deterministic unit tests for key detection/correlation logic
- Practical CI checks (fmt/clippy/build)

## Option 4 — Hardening

Focus: robustness against evasion and operational issues.

- More event sources / telemetry normalization improvements
- Better handling of missing signer metadata and path edge cases
- Reliability under load, crash resilience, state reconciliation
- Safer configuration and migration testing

## Option 3 — Monetization (optional, conservative)

If and only if the open-source core is stable:

- Optional rule feeds (curated, explainable, versioned)
- Enterprise packaging and management ergonomics

Non-goals:
- Cloud dependence for basic protection
- Opaque “AI scoring” without explainable evidence

