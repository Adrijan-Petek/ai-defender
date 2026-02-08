# Sysmon (MVP event source)

AI Defender's MVP collector polls the Sysmon log:

- Log: `Microsoft-Windows-Sysmon/Operational`
- Event IDs:
  - 1: Process Create
  - 3: Network Connect
  - 11: File Create (used as a proxy for file activity; Sysmon does not capture reads by default)

If Sysmon is not installed (or the service can't read the log), AI Defender degrades gracefully and relies on simulations.

## Minimal Sysmon config suggestion

This is a conservative starting point. Adjust to your environment.

Notes:

- To get file activity for browser stores, you must enable FileCreate rules (Event ID 11) and include targets.
- The MVP rules are tuned for the **browser store file names** (e.g., `Login Data`, `Cookies`, `Local State`).

Example (partial) Sysmon config:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />

    <FileCreate onmatch="include">
      <TargetFilename condition="end with">\\Login Data</TargetFilename>
      <TargetFilename condition="end with">\\Cookies</TargetFilename>
      <TargetFilename condition="end with">\\Local State</TargetFilename>
      <TargetFilename condition="end with">\\logins.json</TargetFilename>
      <TargetFilename condition="end with">\\key4.db</TargetFilename>
      <TargetFilename condition="end with">\\cookies.sqlite</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

## Installation (high level)

1) Install Sysmon from Microsoft Sysinternals.
2) Apply your config file.
3) Confirm events appear in Event Viewer under `Microsoft-Windows-Sysmon/Operational`.

AI Defender will automatically pick up new events on its next polling cycle.

