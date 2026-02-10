# Contributing guide

This repository welcomes contributions from security engineers and developers. The goal is to keep the project reviewable, safe by default, and easy to recover from.

## Scope rules for contributions

- Do not add offensive capabilities (“hacking back”, stealth, spyware behavior).
- Prefer explainable, deterministic detections over opaque scoring.
- Any change that affects containment behavior must be explicitly called out and reviewed carefully.

## Development setup

See `docs/DEVELOPMENT.md` for build commands, CLI examples, and file locations.

## Pull requests

- Keep PRs small and focused.
- Include tests for logic changes (deterministic unit tests preferred).
- Update docs when behavior or UX changes.
- Avoid adding new dependencies unless clearly justified.

## Labels (recommended)

Suggested labels to use for issues and PRs:

- `bug`, `security`, `documentation`, `tests`, `ux`, `good first issue`
- `agent-core`, `scanner`, `ui`, `kill-switch`, `rules`
- `needs-repro`, `needs-design`, `needs-review`

