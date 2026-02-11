# Uninstall

AI Defender uninstall must leave the system in a safe, unblocked state.

## Required cleanup

Uninstall removes or attempts to remove:

- `AI_DEFENDER_AGENT` service (stop + unregister)
- AI Defender tray startup entry
- AI Defender binaries in install directory
- AI Defender firewall kill switch rules by group only:
  - `AI_DEFENDER_KILLSWITCH`
- Legacy scheduled task name (if present):
  - `AI Defender Tray`

Network safety requirement:

- Uninstall must not leave AI Defender network block rules behind.

## ProgramData behavior

By default, ProgramData state is preserved for audit/recovery:

- `C:\ProgramData\AI Defender\`

Optional full cleanup is supported with installer property:

- `REMOVE_PROGRAMDATA=1`

When enabled, uninstall also removes ProgramData state, logs, license files, and threat-feed files.

## User-facing uninstall choice

Default behavior keeps ProgramData (recommended).  
To remove ProgramData, run uninstall with:

```powershell
msiexec /x {PRODUCT-CODE} REMOVE_PROGRAMDATA=1
```

## Emergency manual recovery (Administrator)

If uninstall cannot run and networking is locked:

```powershell
netsh advfirewall firewall delete rule group="AI_DEFENDER_KILLSWITCH"
```

This command only targets rules in AI Defender's firewall group.
