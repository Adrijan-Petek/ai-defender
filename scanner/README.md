# Scanner (on-demand)

On-demand, offline scanner for AI Defender.

## Safety rules

- Scanner findings alone never auto-trigger containment (no kill switch).
- Scanner reports findings as local incidents (usually YELLOW).
- No cloud dependency and no outbound network calls.
- No file contents are read beyond hashing.

## Commands

- Quick scan: `scanner --quick`
- Full scan: `scanner --full`
- Cancelable scans: `scanner --quick --cancel-file "C:\Path\to\cancel.flag"`
  - Create the file to request cancellation.

## Output

- Prints periodic `PROGRESS ...` lines to stdout.
- Stores incidents under `C:\ProgramData\AI Defender\incidents\`.

