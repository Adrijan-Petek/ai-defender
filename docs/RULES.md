# Rules (R001–R010)

AI Defender rules are designed to be:

- **Explainable:** each detection has a stable rule ID and a concrete reason.
- **Reviewable:** security engineers can reason about inputs and outputs.
- **Reversible:** actions taken are explicit and should be safe to undo.

This document describes v1 rule IDs and their intent. Rule implementations live in `agent-core/src/rules_engine/`.

## Severity policy

- **Learning mode:** monitoring and incident recording; no automatic containment.
- **Strict mode:** automatic response is limited to **RED** incidents (see `docs/LEARNING_VS_STRICT.md`).

Severity indicates confidence and potential impact, not “maliciousness certainty”.

## Rule list

### R001 — Non-browser process reads Chromium Login Data

- **Intent:** detect access to Chromium credential store.
- **Data needed:** file access event for a path ending in `Login Data` under a Chromium-family profile directory.
- **Severity policy:** `YELLOW` in learning; intended as a signal for correlation.

### R002 — Non-browser process reads Chromium Cookies

- **Intent:** detect cookie database access (session hijack).
- **Data needed:** file access event for a path ending in `Cookies` under a Chromium-family profile directory.
- **Severity policy:** `YELLOW` in learning; intended as a signal for correlation.

### R003 — Non-browser process reads Chromium Local State

- **Intent:** detect access to Chromium `Local State` which can be used to locate/unwrap protected material.
- **Data needed:** file access event for a path ending in `Local State` under a Chromium-family profile directory.
- **Severity policy:** `YELLOW` in learning; intended as a signal for correlation.

### R004 — Non-browser process reads Firefox `logins.json`

- **Intent:** detect access to Firefox credential metadata.
- **Data needed:** file access event for a path ending in `logins.json` under Firefox profiles.
- **Severity policy:** `YELLOW` in learning; intended as a signal for correlation.

### R005 — Non-browser process reads Firefox `key4.db`

- **Intent:** detect access to Firefox key material store.
- **Data needed:** file access event for a path ending in `key4.db` under Firefox profiles.
- **Severity policy:** `YELLOW` in learning; intended as a signal for correlation.

### R006 — Reserved (not implemented in v1)

- **Intent:** reserved for a future rule ID to keep numbering stable for documentation and triage.
- **Data needed:** N/A
- **Severity policy:** N/A

### R007 — High-rate enumeration under browser profile directories

- **Intent:** detect broad scanning/enumeration of browser profile roots (often a precursor to targeted reads).
- **Data needed:** repeated file access events under protected roots within a short window.
- **Severity policy:** `YELLOW` (signal for investigation/correlation).

### R008 — Unknown/unsigned publisher touched protected browser target

- **Intent:** raise visibility when the signer publisher is missing/unknown on access to protected targets.
- **Data needed:** file access event + missing signer publisher string.
- **Severity policy:** `YELLOW`

### R009 — Sensitive access followed by outbound network connection

- **Intent:** identify a high-confidence theft/exfil chain.
- **Data needed:** recent sensitive access evidence + subsequent outbound network connection by the same PID within the correlation window.
- **Severity policy:** `RED` (used for strict-mode response gating).

### R010 — Outbound connection after sensitive access to direct IP / unknown host

- **Intent:** strengthen confidence when the destination host is missing/empty (e.g., direct IP).
- **Data needed:** outbound network event with missing/empty `dest_host` following sensitive access.
- **Severity policy:** `RED`

## Why rules must be explainable and reversible

For endpoint defenses, trust and correctness depend on:

- Clear incident reasoning (what was accessed, what network connection followed, and why that matters).
- Minimal surprise in enforcement (safe defaults, explicit strict mode).
- A reliable recovery path (containment can be disabled via UI or CLI).

