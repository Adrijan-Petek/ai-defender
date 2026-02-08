# Uninstall

Uninstall must be clean and reversible.

Expected uninstall actions:

- Stop and remove the `AI_DEFENDER_AGENT` service
- Remove AI Defender kill switch firewall rules (group `AI_DEFENDER_KILLSWITCH`)
- Remove tray UI autostart entry
- Remove installed binaries
- Optionally remove `C:\ProgramData\AI Defender\` (state/logs/incidents)

## Emergency firewall cleanup (Administrator)

If the network is locked and you cannot use the UI:

- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Outbound" group="AI_DEFENDER_KILLSWITCH"`
- `netsh advfirewall firewall delete rule name="AI Defender KillSwitch Inbound" group="AI_DEFENDER_KILLSWITCH"`

