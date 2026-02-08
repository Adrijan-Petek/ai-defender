namespace AI.Defender.Tray;

internal static class AgentFiles
{
  public static string BaseDir =>
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AI Defender");

  public static string ConfigPath => Path.Combine(BaseDir, "config.toml");
  public static string KillSwitchStatePath => Path.Combine(BaseDir, "killswitch-state.toml");
  public static string LogsDir => Path.Combine(BaseDir, "logs");
  public static string IncidentsDir => Path.Combine(BaseDir, "incidents");

  public static AgentConfig? TryReadConfig()
  {
    try
    {
      if (!File.Exists(ConfigPath))
      {
        return null;
      }
      var text = File.ReadAllText(ConfigPath);
      return TomlMini.ParseConfig(text);
    }
    catch
    {
      return null;
    }
  }

  public static bool TrySetMode(AgentMode mode, out string? error)
  {
    error = null;
    try
    {
      Directory.CreateDirectory(BaseDir);
      var current = File.Exists(ConfigPath) ? File.ReadAllText(ConfigPath) : "";
      var updated = TomlMini.SetTopLevelString(current, "mode", mode == AgentMode.Strict ? "strict" : "learning");
      File.WriteAllText(ConfigPath, updated);
      return true;
    }
    catch (Exception ex)
    {
      error = ex.Message;
      return false;
    }
  }

  public static KillSwitchState? TryReadKillSwitchState()
  {
    try
    {
      if (!File.Exists(KillSwitchStatePath))
      {
        return null;
      }
      var text = File.ReadAllText(KillSwitchStatePath);
      return TomlMini.ParseKillSwitchState(text);
    }
    catch
    {
      return null;
    }
  }

  public static IncidentSummary? TryReadLastIncidentSummary()
  {
    try
    {
      if (!Directory.Exists(IncidentsDir))
      {
        return null;
      }
      var file = Directory
        .EnumerateFiles(IncidentsDir, "*.toml", SearchOption.TopDirectoryOnly)
        .Select(p => new FileInfo(p))
        .OrderByDescending(fi => fi.LastWriteTimeUtc)
        .FirstOrDefault();

      if (file is null)
      {
        return null;
      }

      var text = File.ReadAllText(file.FullName);
      return TomlMini.ParseIncidentSummary(text);
    }
    catch
    {
      return null;
    }
  }
}

internal enum AgentMode
{
  Unknown = 0,
  Learning,
  Strict
}

internal sealed record AgentConfig(AgentMode Mode);

internal sealed record KillSwitchState(
  bool Enabled,
  bool KeepLocked,
  string? EnabledMode,
  ulong? EnabledAtUnixMs,
  ulong? FailsafeDeadlineUnixMs,
  string? LastIncidentId);

internal sealed record IncidentSummary(
  string IncidentId,
  string Severity,
  ulong CreatedAtUnixMs,
  IReadOnlyList<string> RuleIds,
  IReadOnlyList<string> ActionsTaken);
