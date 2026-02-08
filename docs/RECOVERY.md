# Recovery

## Kill switch recovery

Preferred (uses AI Defender):

- `cargo run -p agent-core -- --console --killswitch off`

Emergency (no agent required, run as Administrator):

- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Outbound" group="AI_DEFENDER_KILLSWITCH"`
- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Inbound" group="AI_DEFENDER_KILLSWITCH"`

These commands remove only AI Defender's kill switch rules.

## Locations

- Config: `C:\ProgramData\AI Defender\config.toml`
- Logs: `C:\ProgramData\AI Defender\logs\agent-core.log.YYYY-MM-DD`
- Kill switch state: `C:\ProgramData\AI Defender\killswitch-state.toml`
- Incidents: `C:\ProgramData\AI Defender\incidents\{incident_id}.toml`

