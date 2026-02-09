using System.Diagnostics;

namespace AI.Defender.Tray;

internal static class AgentCli
{
  // MVP: UI talks to the agent via local CLI invocation. No network is used.
  // The tray app never assumes success; it validates by checking state files after running commands.
  private static string? FindAgentExe()
  {
    var exeDir = AppContext.BaseDirectory;
    var candidate = Path.Combine(exeDir, "agent-core.exe");
    if (File.Exists(candidate))
    {
      return candidate;
    }

    // Dev-friendly fallback: if running from repo, this may be present after `cargo build`.
    var repoCandidate = Path.GetFullPath(Path.Combine(exeDir, "..", "..", "..", "..", "target", "release", "agent-core.exe"));
    if (File.Exists(repoCandidate))
    {
      return repoCandidate;
    }

    return null;
  }

  public static bool IsAvailable() => FindAgentExe() is not null;

  public static AgentCliResult Run(params string[] args)
  {
    var exe = FindAgentExe();
    if (exe is null)
    {
      return AgentCliResult.Fail(
        "Agent executable not found.\n\n" +
        "Expected `agent-core.exe` next to the tray UI executable (recommended for MVP installs).");
    }

    try
    {
      var psi = new ProcessStartInfo(exe)
      {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
      };
      foreach (var a in args)
      {
        psi.ArgumentList.Add(a);
      }

      using var p = Process.Start(psi);
      if (p is null)
      {
        return AgentCliResult.Fail("Failed to start agent process.");
      }

      if (!p.WaitForExit(10_000))
      {
        try { p.Kill(entireProcessTree: true); } catch { }
        return AgentCliResult.Fail("Agent command timed out.");
      }

      var stdout = p.StandardOutput.ReadToEnd();
      var stderr = p.StandardError.ReadToEnd();
      if (p.ExitCode != 0)
      {
        var msg = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
        msg = string.IsNullOrWhiteSpace(msg) ? "Agent returned a non-zero exit code." : msg.Trim();
        return AgentCliResult.Fail(msg);
      }

      return AgentCliResult.Ok();
    }
    catch (Exception ex)
    {
      return AgentCliResult.Fail($"Agent command failed: {ex.Message}");
    }
  }

  public static string? TryGetVersion()
  {
    var exe = FindAgentExe();
    if (exe is null)
    {
      return null;
    }

    try
    {
      var psi = new ProcessStartInfo(exe)
      {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
      };
      psi.ArgumentList.Add("--version");

      using var p = Process.Start(psi);
      if (p is null)
      {
        return null;
      }
      if (!p.WaitForExit(5_000))
      {
        try { p.Kill(entireProcessTree: true); } catch { }
        return null;
      }
      if (p.ExitCode != 0)
      {
        return null;
      }
      var v = p.StandardOutput.ReadToEnd().Trim();
      return string.IsNullOrWhiteSpace(v) ? null : v;
    }
    catch
    {
      return null;
    }
  }
}

internal sealed record AgentCliResult(bool Success, string UserMessage)
{
  public static AgentCliResult Ok() => new(true, "");
  public static AgentCliResult Fail(string msg) => new(false, msg);
}
