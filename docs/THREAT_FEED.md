# Threat Feed (offline-first)

AI Defender supports signed threat feed bundles that can be imported from local files.
This phase is offline-first: there are no automatic downloads and no network calls.

## Bundle files

A bundle is two files:

- `bundle.json`
- `bundle.sig` (Ed25519 signature over the exact bytes of `bundle.json`)

Storage location:

- `C:\ProgramData\AI Defender\threat-feed\bundle.json`
- `C:\ProgramData\AI Defender\threat-feed\bundle.sig`
- `C:\ProgramData\AI Defender\threat-feed\bundle.meta.json`

## Bundle schema (v1)

`bundle.json`:

```json
{
  "version": 1,
  "bundle_id": "uuid",
  "created_at": 1700000000,
  "rules_version": 12,
  "reputation": {
    "domains_block": ["example.bad"],
    "hashes_block": ["sha256:..."],
    "wallet_spenders_block": ["0x..."]
  },
  "rules": [
    {
      "rule_id": "R001",
      "enabled": true,
      "severity_floor": "yellow",
      "severity_cap_learning": "yellow",
      "severity_strict": "yellow",
      "notes": "optional"
    }
  ]
}
```

Rules in the bundle only configure existing logic (enable/disable and severity controls). This does not add new detection behavior.

## Verification and safety policy

On import, the agent performs:

1. Ed25519 signature verification with an embedded public key.
2. Schema validation for required fields.
3. Version compatibility check (`version == 1`).

If verification fails:

- The import is rejected.
- Existing installed bundle remains unchanged.
- Agent continues with last known-good data.

If no valid bundle exists, the agent uses empty/default reputation lists.

## Manual CLI usage

Verify a bundle:

```powershell
agent-core.exe --console --feed verify C:\path\bundle.json C:\path\bundle.sig
```

Import a bundle:

```powershell
agent-core.exe --console --feed import C:\path\bundle.json C:\path\bundle.sig
```

Show status:

```powershell
agent-core.exe --console --feed status
```

## Privacy

By default:

- No bundle data is uploaded.
- No telemetry is sent.
- No outbound network calls are required for threat feed usage.

A paid service may later automate bundle delivery, but that delivery path is not implemented in this phase.
