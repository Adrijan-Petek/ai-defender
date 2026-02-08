using System.Diagnostics;

namespace AI.Defender.Tray;

internal enum ScanMode
{
  Quick = 0,
  Full
}

internal sealed class ScannerCli
{
  private readonly Process _process;
  private readonly string _cancelFile;

  private ScannerCli(Process process, string cancelFile)
  {
    _process = process;
    _cancelFile = cancelFile;
  }

  public Process Process => _process;
  public string CancelFile => _cancelFile;

  public static ScannerCliResult Start(ScanMode mode)
  {
    var exe = FindScannerExe();
    if (exe is null)
    {
      return ScannerCliResult.Fail(
        "Scanner executable not found.\n\n" +
        "Expected `scanner.exe` next to the tray UI executable (recommended for MVP installs).");
    }

    var cancelFile = Path.Combine(Path.GetTempPath(), $"ai-defender-scan-cancel-{Guid.NewGuid():N}.flag");

    var psi = new ProcessStartInfo(exe)
    {
      UseShellExecute = false,
      RedirectStandardOutput = true,
      RedirectStandardError = true,
      CreateNoWindow = true
    };

    psi.ArgumentList.Add(mode == ScanMode.Quick ? "--quick" : "--full");
    psi.ArgumentList.Add("--cancel-file");
    psi.ArgumentList.Add(cancelFile);

    try
    {
      var p = Process.Start(psi);
      if (p is null)
      {
        return ScannerCliResult.Fail("Failed to start scanner process.");
      }
      return ScannerCliResult.Ok(new ScannerCli(p, cancelFile));
    }
    catch (Exception ex)
    {
      return ScannerCliResult.Fail($"Scanner start failed: {ex.Message}");
    }
  }

  public void RequestCancel()
  {
    try
    {
      File.WriteAllText(_cancelFile, "cancel");
    }
    catch
    {
      // best-effort
    }
  }

  private static string? FindScannerExe()
  {
    var exeDir = AppContext.BaseDirectory;
    var candidate = Path.Combine(exeDir, "scanner.exe");
    if (File.Exists(candidate))
    {
      return candidate;
    }

    var repoCandidate = Path.GetFullPath(Path.Combine(exeDir, "..", "..", "..", "..", "target", "release", "scanner.exe"));
    if (File.Exists(repoCandidate))
    {
      return repoCandidate;
    }

    return null;
  }
}

internal sealed record ScannerCliResult(bool Success, string UserMessage, ScannerCli? Cli)
{
  public static ScannerCliResult Ok(ScannerCli cli) => new(true, "", cli);
  public static ScannerCliResult Fail(string msg) => new(false, msg, null);
}

