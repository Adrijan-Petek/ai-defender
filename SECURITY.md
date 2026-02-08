# Security Policy

AI Defender is an early-stage endpoint security engine. Please read this policy before reporting issues.

## Threat model (high level)

AI Defender is **behavior-based**. It does not attempt to “detect AI”.

The MVP focuses on chains that theft malware cannot avoid:

- sensitive local access (e.g., browser credential/cookie stores)
- followed by outbound network activity shortly after

## Privacy and telemetry

- No hidden telemetry.
- No cloud dependency required for core protection.
- No data exfiltration by default.
- No clipboard contents and no file contents are logged.

## Reporting a vulnerability

Please report security issues responsibly:

1) Do **not** open a public GitHub issue for a vulnerability.
2) Email: **security@EXAMPLE.invalid** (replace with a real address before release).
3) Include:
   - affected version/commit
   - reproduction steps
   - impact assessment
   - any logs (redact sensitive info)

## Supported versions

This repository is early-stage. Only the latest `main` branch is considered supported for security fixes.

