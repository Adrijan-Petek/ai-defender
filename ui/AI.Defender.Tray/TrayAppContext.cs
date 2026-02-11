using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

namespace AI.Defender.Tray;

internal sealed class TrayAppContext : ApplicationContext
{
  private readonly NotifyIcon _notifyIcon;
  private readonly System.Windows.Forms.Timer _timer;

  private readonly ToolStripMenuItem _statusItem;
  private readonly ToolStripMenuItem _lockNowItem;
  private readonly ToolStripMenuItem _restoreItem;
  private readonly ToolStripMenuItem _toggleModeItem;
  private readonly ToolStripMenuItem _lastIncidentItem;

  private Icon? _currentIcon;
  private IconFactory.Badge _currentBadge = IconFactory.Badge.None;

  private AgentStatusSnapshot _snapshot = AgentStatusSnapshot.Empty;

  public TrayAppContext()
  {
    _statusItem = new ToolStripMenuItem("Status");
    _lockNowItem = new ToolStripMenuItem("Enable Kill Switch NOW");
    _restoreItem = new ToolStripMenuItem("Restore Network");
    _toggleModeItem = new ToolStripMenuItem("Toggle Learning / Strict Mode");
    _lastIncidentItem = new ToolStripMenuItem("View Last Incident");

    var openLogs = new ToolStripMenuItem("Open Logs Folder");
    var exit = new ToolStripMenuItem("Exit UI");

    _statusItem.Click += (_, _) => ShowStatus();
    _lockNowItem.Click += (_, _) => EnableKillSwitchWithConfirm();
    _restoreItem.Click += (_, _) => RestoreKillSwitchWithConfirm();
    _toggleModeItem.Click += (_, _) => ToggleModeWithConfirm();
    _lastIncidentItem.Click += (_, _) => ShowLastIncident();
    openLogs.Click += (_, _) => OpenLogsFolder();
    exit.Click += (_, _) => ExitThread();

    var menu = new ContextMenuStrip();
    menu.Items.AddRange(new ToolStripItem[]
    {
      _statusItem,
      _lockNowItem,
      _restoreItem,
      _toggleModeItem,
      _lastIncidentItem,
      openLogs,
      exit
    });

    _notifyIcon = new NotifyIcon
    {
      Text = "AI Defender",
      Icon = IconFactory.CreateTrayIcon(),
      ContextMenuStrip = menu,
      Visible = true
    };
    _currentIcon = _notifyIcon.Icon;
    _notifyIcon.DoubleClick += (_, _) => ShowStatus();

    _timer = new System.Windows.Forms.Timer { Interval = 4_000 };
    _timer.Tick += (_, _) => RefreshStatus();
    _timer.Start();

    RefreshStatus();
  }

  protected override void Dispose(bool disposing)
  {
    if (disposing)
    {
      _timer.Stop();
      _timer.Dispose();
      _notifyIcon.Visible = false;
      _notifyIcon.Dispose();
      _currentIcon?.Dispose();
    }
    base.Dispose(disposing);
  }

  private void RefreshStatus()
  {
    try
    {
      var service = GetServiceState();
      var cfg = AgentFiles.TryReadConfig();
      var kill = AgentFiles.TryReadKillSwitchState();
      var last = AgentFiles.TryReadLastIncidentSummary();

      var agentRunning = service == ServiceControllerStatus.Running;
      var serviceDetail = service is null ? "Service not found or not installed." : null;

      _snapshot = new AgentStatusSnapshot(
        AgentRunning: agentRunning,
        ServiceState: service,
        Mode: cfg?.Mode ?? AgentMode.Unknown,
        KillSwitchEnabled: kill?.Enabled == true,
        LastIncidentSummary: last,
        ServiceDetail: serviceDetail);

      var (tooltip, badge) = ComputeTrayPresentation(_snapshot);
      _notifyIcon.Text = tooltip.Length > 60 ? tooltip[..60] : tooltip;

      ApplyMenuState(_snapshot);
      SetIconBadge(badge);
    }
    catch
    {
      _snapshot = AgentStatusSnapshot.Empty with
      {
        ServiceState = null,
        ServiceDetail = "Status refresh failed unexpectedly."
      };
      _notifyIcon.Text = "Agent Not Running";
      ApplyMenuState(_snapshot);
      SetIconBadge(IconFactory.Badge.Gray);
    }
  }

  private static (string Tooltip, IconFactory.Badge Badge) ComputeTrayPresentation(AgentStatusSnapshot s)
  {
    if (IsServiceTransitioning(s.ServiceState))
    {
      return ("Agent Service Restarting", IconFactory.Badge.Gray);
    }

    if (!s.AgentRunning)
    {
      return ("Agent Not Running", IconFactory.Badge.Gray);
    }

    if (s.KillSwitchEnabled)
    {
      return ("Network Locked - Kill Switch Active", IconFactory.Badge.Red);
    }

    var mode = s.Mode == AgentMode.Unknown ? AgentMode.Learning : s.Mode;
    return mode switch
    {
      AgentMode.Strict => ("Strict Mode - Auto Response Enabled", IconFactory.Badge.Blue),
      _ => ("Learning Mode - Monitoring Only", IconFactory.Badge.Green)
    };
  }

  private void ApplyMenuState(AgentStatusSnapshot s)
  {
    var cliAvailable = AgentCli.IsAvailable();
    var transitioning = IsServiceTransitioning(s.ServiceState);

    _lockNowItem.Enabled = s.AgentRunning && cliAvailable && !transitioning;
    _toggleModeItem.Enabled = s.AgentRunning && !transitioning;

    _restoreItem.Enabled = cliAvailable && !transitioning && (!s.AgentRunning || s.KillSwitchEnabled);

    _lastIncidentItem.Enabled = true;
  }

  private static bool IsServiceTransitioning(ServiceControllerStatus? status)
  {
    return status is ServiceControllerStatus.StartPending
      or ServiceControllerStatus.StopPending
      or ServiceControllerStatus.ContinuePending
      or ServiceControllerStatus.PausePending;
  }

  private void SetIconBadge(IconFactory.Badge badge)
  {
    if (badge == _currentBadge)
    {
      return;
    }

    var newIcon = IconFactory.CreateTrayIcon(badge);
    var old = _currentIcon;
    _notifyIcon.Icon = newIcon;
    _currentIcon = newIcon;
    _currentBadge = badge;
    old?.Dispose();
  }

  private static ServiceControllerStatus? GetServiceState()
  {
    try
    {
      using var sc = new ServiceController(ProductInfo.ServiceName);
      return sc.Status;
    }
    catch
    {
      return null;
    }
  }

  private void ToggleModeWithConfirm()
  {
    if (!_snapshot.AgentRunning)
    {
      MessageBox.Show(
        "The AI Defender agent is not running.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Information);
      return;
    }

    var cfg = AgentFiles.TryReadConfig();
    if (cfg is null || cfg.Mode == AgentMode.Unknown)
    {
      MessageBox.Show(
        "Unable to read current mode from config.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    var next = cfg.Mode == AgentMode.Learning ? AgentMode.Strict : AgentMode.Learning;
    var title = "AI Defender - Change Mode";
    var body = next == AgentMode.Strict
      ? "Switch to Strict mode?\n\n" +
        "Strict mode may trigger automatic response for high-confidence RED incidents. This can include network lock (kill switch).\n\n" +
        "Proceed?"
      : "Switch back to Learning mode?\n\n" +
        "Learning mode monitors and records incidents, and does not auto-trigger the kill switch.\n\n" +
        "Proceed?";

    var icon = next == AgentMode.Strict ? MessageBoxIcon.Warning : MessageBoxIcon.Question;
    if (MessageBox.Show(body, title, MessageBoxButtons.YesNo, icon) != DialogResult.Yes)
    {
      return;
    }

    var ok = AgentFiles.TrySetMode(next, out var err);
    if (!ok)
    {
      MessageBox.Show(err ?? "Failed to update config.", "AI Defender", MessageBoxButtons.OK, MessageBoxIcon.Error);
      return;
    }

    var restart = MessageBox.Show(
      "Mode updated in config. Restart the AI Defender service to apply now?\n\n" +
      "If you choose No, it will apply on next service restart/reboot.",
      "AI Defender - Restart Service",
      MessageBoxButtons.YesNo,
      MessageBoxIcon.Question);

    if (restart == DialogResult.Yes)
    {
      TryRestartService();
    }

    RefreshStatus();
  }

  private static void TryRestartService()
  {
    try
    {
      using var sc = new ServiceController(ProductInfo.ServiceName);
      if (sc.Status == ServiceControllerStatus.Running)
      {
        sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
      }
      sc.Start();
      sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
    }
    catch
    {
      MessageBox.Show(
        "Unable to restart the service automatically (may require Administrator privileges).\n\n" +
        "You can restart it from Services (services.msc) or reboot.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Information);
    }
  }

  private void EnableKillSwitchWithConfirm()
  {
    if (!AgentCli.IsAvailable())
    {
      MessageBox.Show(
        "Agent executable not found. Kill switch commands are unavailable.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    var msg =
      "Enable kill switch now?\n\n" +
      "This immediately blocks all inbound and outbound network traffic using Windows Firewall.\n\n" +
      "Proceed?";

    var res = MessageBox.Show(msg, "AI Defender - Enable Kill Switch", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
    if (res != DialogResult.Yes)
    {
      return;
    }

    var r = AgentCli.Run("--console", "--killswitch", "on");
    if (!r.Success)
    {
      MessageBox.Show(
        r.UserMessage,
        "AI Defender - Action Failed",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    WaitForKillSwitchState(expectedEnabled: true);
    RefreshStatus();
    if (!_snapshot.KillSwitchEnabled)
    {
      MessageBox.Show(
        "Kill switch command completed, but the UI could not confirm lock state.\n\n" +
        "Open Status to verify or use recovery steps.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Warning);
      return;
    }

    MessageBox.Show(
      "Network locked. You can restore networking via the tray menu.",
      "AI Defender - Network Locked",
      MessageBoxButtons.OK,
      MessageBoxIcon.Information);
  }

  private void RestoreKillSwitchWithConfirm()
  {
    if (!AgentCli.IsAvailable())
    {
      MessageBox.Show(
        "Agent executable not found. Kill switch commands are unavailable.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    if (!_snapshot.KillSwitchEnabled && _snapshot.AgentRunning)
    {
      MessageBox.Show(
        "Kill switch is already disabled.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Information);
      return;
    }

    var res = MessageBox.Show(
      "Restore network access by removing AI Defender kill switch firewall rules?",
      "AI Defender - Restore Network",
      MessageBoxButtons.YesNo,
      MessageBoxIcon.Question);

    if (res != DialogResult.Yes)
    {
      return;
    }

    var r = AgentCli.Run("--console", "--killswitch", "off");
    if (!r.Success)
    {
      MessageBox.Show(
        r.UserMessage,
        "AI Defender - Action Failed",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    WaitForKillSwitchState(expectedEnabled: false);
    RefreshStatus();
    if (_snapshot.KillSwitchEnabled)
    {
      MessageBox.Show(
        "Restore command completed, but the UI could not confirm that networking is restored.\n\n" +
        "Open Status to verify or use recovery steps.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Warning);
      return;
    }

    MessageBox.Show(
      "Networking should be restored.",
      "AI Defender - Network Restored",
      MessageBoxButtons.OK,
      MessageBoxIcon.Information);
  }

  private static void WaitForKillSwitchState(bool expectedEnabled)
  {
    var sw = Stopwatch.StartNew();
    while (sw.ElapsedMilliseconds < 2_000)
    {
      var st = AgentFiles.TryReadKillSwitchState();
      var enabled = st?.Enabled == true;
      if (enabled == expectedEnabled)
      {
        return;
      }
      Thread.Sleep(100);
    }
  }

  private void ShowStatus()
  {
    RefreshStatus();
    using var dlg = new StatusDialog(_snapshot);
    dlg.ShowDialog();
  }

  private void ShowLastIncident()
  {
    var last = AgentFiles.TryReadLastIncidentSummary();
    using var dlg = new IncidentDialog(last);
    dlg.ShowDialog();
  }

  private static void OpenLogsFolder()
  {
    var path = AgentFiles.LogsDir;
    try
    {
      Directory.CreateDirectory(path);
      Process.Start(new ProcessStartInfo("explorer.exe", path) { UseShellExecute = true });
    }
    catch
    {
      MessageBox.Show(
        $"Unable to open logs folder:\n{path}",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
    }
  }
}

internal sealed record AgentStatusSnapshot(
  bool AgentRunning,
  ServiceControllerStatus? ServiceState,
  AgentMode Mode,
  bool KillSwitchEnabled,
  IncidentSummary? LastIncidentSummary,
  string? ServiceDetail)
{
  public static AgentStatusSnapshot Empty => new(
    AgentRunning: false,
    ServiceState: null,
    Mode: AgentMode.Unknown,
    KillSwitchEnabled: false,
    LastIncidentSummary: null,
    ServiceDetail: null);
}
