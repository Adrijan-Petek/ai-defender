# Threat model

AI Defender is defensive endpoint security focused on explainable, behavior-based detection. It does not rely on “AI malware classification” in v1.

## Attacker model

The primary assumed adversary is user-mode malware operating on a Windows endpoint, including:

- **AI-assisted malware**: uses LLMs to generate/modify code, evade static signatures, and automate targeting.
- **Wallet drainers**: attempt to steal browser-stored credentials/cookies and local wallet artifacts, then exfiltrate.
- **Cookie/credential theft**: targets browser profile stores (Chromium and Firefox families) to hijack sessions.

We assume adversaries can:

- Execute as the current user (or as a child of a user-launched process).
- Use commodity stealth (renaming, packing, living-off-the-land tooling).
- Perform outbound network connections to exfiltrate data.

We do not assume kernel-level attackers in v1.

## Key threats

- **Data exfiltration:** credentials/cookies/keys read locally, then sent out over the network.
- **Stealth collection:** slow, low-noise collection across multiple stores over time.
- **Prompt injection / social engineering around security tooling:** attempts to convince a user or operator to run unsafe commands or disable protections.
- **Abuse of allowlists and exclusions:** adversary attempts to appear “trusted” (publisher strings, paths) to avoid detection.

## What AI Defender focuses on (v1)

AI Defender prioritizes high-confidence behavior chains. A common chain is:

1) A **non-browser process** accesses sensitive browser storage, then
2) The **same process** makes an outbound network connection within a short correlation window.

This approach is intended to reduce false positives and keep detections explainable.

## Non-goals (v1)

- Offensive actions, retaliation, or “hacking back”.
- Stealth monitoring of users, “spying”, or collecting personal content.
- Kernel drivers.
- Cloud services or remote telemetry pipelines as a requirement for basic operation.

## Trust principles

- **Transparency:** detections are rule-based and explainable; incidents record rule IDs and actions taken.
- **Least privilege:** run with only what is required; changes to the firewall are explicit and reversible.
- **Safe defaults:** learning mode is the default; strict mode is opt-in.
- **Clear recovery:** documented steps to restore networking if containment is enabled.

