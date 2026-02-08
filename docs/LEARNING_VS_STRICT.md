# Learning vs strict

AI Defender starts in **learning** mode by default.

## Learning mode (default)

- Incidents are still detected and stored locally.
- No automatic enforcement is performed (no auto kill switch), even on RED.
- Manual kill switch remains available.

## Strict mode (opt-in)

- If an incident is **RED** and `killswitch.auto_trigger = true`, AI Defender may auto-enable the kill switch.
- YELLOW incidents still never trigger enforcement.

## Why default to learning

Endpoint security must be predictable and trustworthy. Learning mode reduces the risk of false positives causing network disruption.

