# Threat model (MVP)

AI Defender is **defensive endpoint security** focused on detecting **behavior chains**, not "AI".

## Core attacker goal

Steal sensitive local data (credentials/cookies/wallet artifacts) and exfiltrate it over the network, often silently.

## MVP detection idea

High-confidence theft usually requires a short chain:

1) A non-browser process touches sensitive browser storage (credentials/cookies/local key material), then
2) That same process makes an outbound network connection shortly after.

The MVP focuses on this chain. Single events (e.g., a process start) are not enough to trigger enforcement.

## Safety principles

- Default mode is **learning**: log/record incidents, no automatic network blocking.
- Strict mode is opt-in and only auto-responds to **RED** incidents.
- No secrets are logged (no clipboard contents, no file contents).

