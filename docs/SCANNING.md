# Scanning

AI Defender includes an on-demand scanner (`scanner.exe`).

## Safety rules

- Scanner findings alone never auto-trigger containment (no kill switch).
- Scanner runs at low priority and is cancelable.
- Scanner is offline-first and does not upload data.

## Scan types

- Quick Scan:
  - Startup folders
  - Program Files
  - User AppData
  - Browser extension directories
- Full Scan:
  - All fixed drives (supports exclusions via CLI)

## What the scanner checks (MVP)

- SHA-256 hashing
- Basic Authenticode trust check (signed vs unsigned)
- Heuristics:
  - unsigned executables/scripts
  - executables in user-writable directories (Temp/AppData)
  - executables in Startup folders

## Output

Scanner writes findings as local incidents under `C:\ProgramData\AI Defender\incidents\`.

