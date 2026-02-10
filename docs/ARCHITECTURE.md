# Architecture

AI Defender is a local, defensive endpoint security tool for Windows. The Rust agent (`agent-core`) is the source of truth for detection and response logic. The tray UI is a thin control and status surface; it does not implement security logic.

## High-level diagram

```
              ┌──────────────────────────────────────────┐
              │                 Windows                  │
              └──────────────────────────────────────────┘

   Sysmon / ETW / OS signals (future)         Local CLI (MVP)
              │                                    ▲
              ▼                                    │
┌──────────────────────────┐                      │
│       event_collector    │                      │
│  - normalizes telemetry  │                      │
│  - emits Events          │                      │
└─────────────┬────────────┘                      │
              │ Events                            │
              ▼                                   │
┌──────────────────────────┐                      │
│        rules_engine      │                      │
│  - explainable rules     │                      │
│  - produces Findings     │                      │
└─────────────┬────────────┘                      │
              │ Findings                           │
              ▼                                   │
┌──────────────────────────┐                      │
│    correlation store     │                      │
│  - per-process windows   │                      │
│  - chain correlation     │                      │
└─────────────┬────────────┘                      │
              │ Incidents                          │
              ▼                                   │
┌──────────────────────────┐                      │
│      response_engine     │                      │
│  - safe defaults         │                      │
│  - strict is opt-in      │                      │
└─────────────┬────────────┘                      │
              │ Actions                            │
              ▼                                   │
┌──────────────────────────┐                      │
│        kill_switch        │                      │
│  - Windows Firewall rules │                      │
│  - reversible containment │                      │
└─────────────┬────────────┘                      │
              │ state + incidents                  │
              ▼                                   │
     C:\ProgramData\AI Defender\...                │
              ▲                                    │
              │ reads                              │
┌─────────────┴────────────┐                      │
│            ui            │──────────────────────┘
│  - tray status + actions │
│  - confirmations         │
└──────────────────────────┘

┌──────────────────────────┐
│          scanner          │
│  - on-demand scanning     │
│  - reports as incidents   │
└──────────────────────────┘
```

## Component boundaries

- `event_collector` (Rust, `agent-core`)
  - Collects/normalizes host events into internal `Event` records.
  - Goal: produce stable, testable events; avoid embedding policy here.

- `rules_engine` (Rust, `agent-core`)
  - Applies explainable, versioned rules to events.
  - Produces `Finding` records with a rule ID, severity, and evidence.

- Correlation store (Rust, `agent-core`)
  - In-memory per-process windows to correlate multi-step behavior chains.
  - Example: sensitive browser-store access followed by outbound network.

- `response_engine` (Rust, `agent-core`)
  - Converts incidents into safe actions based on configuration and mode.
  - Learning mode defaults to monitoring; strict mode is explicit opt-in.

- `kill_switch` (Rust, `agent-core`)
  - Implements reversible network containment using Windows Firewall rules.
  - Maintains a small state file to support recovery and reconciliation.

- `ui` (C# .NET, `ui/AI.Defender.Tray`)
  - Windows tray UX for status and explicit user-initiated actions.
  - Reads agent-owned state and invokes agent CLI (MVP).
  - Does not contain detection or response logic.

- `scanner` (Rust, `scanner`)
  - On-demand scanning component. Findings are reported via incidents.
  - Not a real-time enforcement path in v1.

## Data flow: Event → Finding → Incident → Action

1) **Event**
   - Normalized telemetry (e.g., file access, process start, network connect).

2) **Finding**
   - A single rule match with an explanation and evidence.
   - Example: “Non-browser process accessed Chromium Login Data”.

3) **Incident**
   - A grouped set of findings, often from correlation over time.
   - Carries severity and an `actions_taken` list (audit trail).

4) **Action**
   - A reversible response chosen by `response_engine`.
   - In v1, the primary action is the network kill switch (Windows Firewall).

## Why no “AI detection”

AI Defender intentionally avoids “black box” AI classification in v1:

- **Explainability:** security engineers must be able to review and reason about a detection.
- **Determinism:** stable rules make testing and incident reproduction practical.
- **Safety:** predictable behavior supports safe defaults and clear recovery steps.
- **Trust:** incidents should state *what happened and why*, not “the model said so”.

The project focuses on behavior chains (what a process did) rather than label-based “AI malware” claims.

