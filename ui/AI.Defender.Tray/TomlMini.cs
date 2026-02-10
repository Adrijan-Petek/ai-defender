using System.Globalization;

namespace AI.Defender.Tray;

// Minimal TOML reader for the small, known AI Defender files.
// This avoids external dependencies (offline-first) and only supports the structures we write.
internal static class TomlMini
{
  public static string SetTopLevelString(string text, string key, string value)
  {
    var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
    var inTop = true;
    var replaced = false;

    for (var i = 0; i < lines.Count; i++)
    {
      var raw = lines[i];
      var t = raw.Trim();
      if (t.StartsWith("[") && t.EndsWith("]"))
      {
        inTop = false;
      }
      if (!inTop)
      {
        continue;
      }
      if (TryKeyValue(t, out var k, out _)
          && string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
      {
        lines[i] = $"{key} = \"{value}\"";
        replaced = true;
        break;
      }
    }

    if (!replaced)
    {
      // Prepend key to keep it clearly visible/auditable.
      var prefix = $"{key} = \"{value}\"";
      if (lines.Count == 0)
      {
        lines.Add(prefix);
      }
      else
      {
        lines.Insert(0, prefix);
      }
    }

    return string.Join(Environment.NewLine, lines);
  }

  public static AgentConfig ParseConfig(string text)
  {
    var mode = AgentMode.Unknown;
    foreach (var line in Lines(text))
    {
      if (TryKeyValue(line, out var key, out var value) && key == "mode")
      {
        mode = value.Trim('"').ToLowerInvariant() switch
        {
          "learning" => AgentMode.Learning,
          "strict" => AgentMode.Strict,
          _ => AgentMode.Unknown
        };
      }
    }
    return new AgentConfig(mode);
  }

  public static KillSwitchState ParseKillSwitchState(string text)
  {
    bool enabled = false;
    bool keepLocked = false;
    string? enabledMode = null;
    ulong? enabledAt = null;
    ulong? deadline = null;
    string? lastIncident = null;

    foreach (var line in Lines(text))
    {
      if (!TryKeyValue(line, out var key, out var value))
      {
        continue;
      }

      switch (key)
      {
        case "enabled":
          enabled = ParseBool(value);
          break;
        case "keep_locked":
          keepLocked = ParseBool(value);
          break;
        case "enabled_mode":
          enabledMode = ParseNullableString(value);
          break;
        case "enabled_at_unix_ms":
          enabledAt = ParseNullableU64(value);
          break;
        case "failsafe_deadline_unix_ms":
          deadline = ParseNullableU64(value);
          break;
        case "last_incident_id":
          lastIncident = ParseNullableString(value);
          break;
      }
    }

    return new KillSwitchState(enabled, keepLocked, enabledMode, enabledAt, deadline, lastIncident);
  }

  public static LicenseState ParseLicenseState(string text)
  {
    bool pro = false;
    string? licenseId = null;
    string? plan = null;
    ulong? expiresAt = null;
    ulong checkedAt = 0;
    string? reason = null;

    foreach (var line in Lines(text))
    {
      if (!TryKeyValue(line, out var key, out var value))
      {
        continue;
      }

      switch (key)
      {
        case "pro":
          pro = ParseBool(value);
          break;
        case "license_id":
          licenseId = ParseNullableString(value);
          break;
        case "plan":
          plan = ParseNullableString(value);
          break;
        case "expires_at_unix_ms":
          expiresAt = ParseNullableU64(value);
          break;
        case "checked_at_unix_ms":
          checkedAt = ParseU64(value);
          break;
        case "reason":
          reason = ParseNullableString(value);
          break;
      }
    }

    return new LicenseState(pro, licenseId, plan, expiresAt, checkedAt, reason);
  }

  public static ThreatFeedState ParseThreatFeedState(string text)
  {
    bool installed = false;
    bool verified = false;
    ulong? version = null;
    ulong? installedAt = null;
    ulong checkedAt = 0;
    string? reason = null;

    foreach (var line in Lines(text))
    {
      if (!TryKeyValue(line, out var key, out var value))
      {
        continue;
      }

      switch (key)
      {
        case "installed":
          installed = ParseBool(value);
          break;
        case "verified":
          verified = ParseBool(value);
          break;
        case "version":
          version = ParseNullableU64(value);
          break;
        case "installed_at_unix_ms":
          installedAt = ParseNullableU64(value);
          break;
        case "checked_at_unix_ms":
          checkedAt = ParseU64(value);
          break;
        case "reason":
          reason = ParseNullableString(value);
          break;
      }
    }

    return new ThreatFeedState(installed, verified, version, installedAt, checkedAt, reason);
  }

  public static IncidentSummary? ParseIncidentSummary(string text)
  {
    string? incidentId = null;
    string? severity = null;
    ulong createdAt = 0;
    var actions = new List<string>();
    var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // Parse top-level keys plus [[findings]] tables.
    bool inFinding = false;
    string? findingRuleId = null;

    foreach (var raw in Lines(text))
    {
      var line = raw.Trim();
      if (line == "[[findings]]")
      {
        if (!string.IsNullOrWhiteSpace(findingRuleId))
        {
          ruleIds.Add(findingRuleId);
        }
        inFinding = true;
        findingRuleId = null;
        continue;
      }

      if (!TryKeyValue(line, out var key, out var value))
      {
        continue;
      }

      if (!inFinding)
      {
        if (key == "incident_id")
        {
          incidentId = value.Trim().Trim('"');
        }
        else if (key == "severity")
        {
          severity = value.Trim().Trim('"');
        }
        else if (key == "created_at_unix_ms")
        {
          ulong.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out createdAt);
        }
        else if (key == "actions_taken")
        {
          actions.AddRange(ParseStringArray(value));
        }
      }
      else
      {
        if (key == "rule_id")
        {
          findingRuleId = value.Trim().Trim('"');
        }
      }
    }

    if (!string.IsNullOrWhiteSpace(findingRuleId))
    {
      ruleIds.Add(findingRuleId);
    }

    if (string.IsNullOrWhiteSpace(incidentId))
    {
      return null;
    }

    return new IncidentSummary(
      incidentId,
      severity ?? "unknown",
      createdAt,
      ruleIds.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToArray(),
      actions.ToArray());
  }

  private static IEnumerable<string> Lines(string text)
  {
    using var sr = new StringReader(text);
    while (sr.ReadLine() is { } line)
    {
      var t = line.Trim();
      if (t.Length == 0 || t.StartsWith("#", StringComparison.Ordinal))
      {
        continue;
      }
      yield return t;
    }
  }

  private static bool TryKeyValue(string line, out string key, out string value)
  {
    key = "";
    value = "";
    var idx = line.IndexOf('=');
    if (idx <= 0)
    {
      return false;
    }
    key = line[..idx].Trim();
    value = line[(idx + 1)..].Trim();
    return key.Length > 0;
  }

  private static bool ParseBool(string v)
  {
    var t = v.Trim().ToLowerInvariant();
    return t == "true" || t == "1" || t == "yes" || t == "on";
  }

  private static string? ParseNullableString(string v)
  {
    var t = v.Trim();
    if (t == "null")
    {
      return null;
    }
    return t.Trim('"');
  }

  private static ulong? ParseNullableU64(string v)
  {
    var t = v.Trim();
    if (t == "null")
    {
      return null;
    }
    if (ulong.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x))
    {
      return x;
    }
    return null;
  }

  private static ulong ParseU64(string v)
  {
    var t = v.Trim();
    if (ulong.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x))
    {
      return x;
    }
    return 0;
  }

  private static IEnumerable<string> ParseStringArray(string v)
  {
    // Supports simple ["a", "b"] arrays on one line.
    var t = v.Trim();
    if (!t.StartsWith("[") || !t.EndsWith("]"))
    {
      return Array.Empty<string>();
    }
    t = t[1..^1].Trim();
    if (t.Length == 0)
    {
      return Array.Empty<string>();
    }
    return t
      .Split(',')
      .Select(s => s.Trim().Trim('"'))
      .Where(s => s.Length > 0)
      .ToArray();
  }
}
