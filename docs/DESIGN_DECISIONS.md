# Design decisions

This document records key design choices for v1 and the reasoning behind them. The goal is reviewability and predictable behavior, not novelty.

## Why Rust for `agent-core`

- **Memory safety for long-lived services:** the agent runs continuously and handles untrusted inputs (paths, process metadata, event streams).
- **Deterministic performance:** predictable latency and low overhead for correlation and rule evaluation.
- **Strong typing for security data:** internal event/finding/incident structures are explicit and testable.
- **Tooling ecosystem:** excellent formatting/linting and mature libraries for serialization, CLI, and service scaffolding.

## Why C# for the tray UI

- **Native Windows UX:** WinForms provides a reliable tray experience with minimal dependencies.
- **Separation of concerns:** the UI is intentionally “thin”; it reads agent-owned state and invokes agent commands.
- **Contributor familiarity:** many Windows security engineers can review and modify a small C# UI quickly.

## Why a firewall kill switch first

- **Reversible containment:** Windows Firewall rule changes can be undone, audited, and recovered.
- **Clear safety envelope:** “network locked” is a straightforward containment state with a clear recovery story.
- **Minimal assumptions:** avoids fragile process termination/quarantine logic in v1.

## Why learning mode is the default

- **Safety:** no automatic containment by default reduces the chance of harming users during early adoption.
- **Tuning:** early versions benefit from collecting explainable incidents to calibrate rules.
- **Trust:** users can see what would have happened before enabling strict behavior.

## Why correlation chains are required for RED

Single telemetry points are often ambiguous. v1 escalates to **RED** only when there is a clear multi-step chain such as:

- Sensitive browser-store access **followed by** outbound network activity within a configured window.

This reduces false positives and produces incidents with clear, reviewable evidence.

