using System.Diagnostics;
using System.ServiceProcess;

namespace AI.Defender.Tray;

internal sealed class TrayAppContext : ApplicationContext
{
  private readonly NotifyIcon _notifyIcon;
  private readonly System.Windows.Forms.Timer _timer;

  private readonly ToolStripMenuItem _statusItem;
  private readonly ToolStripMenuItem _modeItem;
  private readonly ToolStripMenuItem _toggleModeItem;
  private readonly ToolStripMenuItem _lockNowItem;
  private readonly ToolStripMenuItem _restoreItem;
  private readonly ToolStripMenuItem _scanMenu;
  private readonly ToolStripMenuItem _lastIncidentItem;

  private Icon? _currentIcon;

  public TrayAppContext()
  {
    _statusItem = new ToolStripMenuItem("Status: …") { Enabled = false };
    _modeItem = new ToolStripMenuItem("Mode: …") { Enabled = false };
    _toggleModeItem = new ToolStripMenuItem("Toggle Learning / Strict…");
    _lockNowItem = new ToolStripMenuItem("Enable Kill Switch NOW…");
    _restoreItem = new ToolStripMenuItem("Restore Network…");
    _scanMenu = new ToolStripMenuItem("Scan Now");
    _lastIncidentItem = new ToolStripMenuItem("View Last Incident…");

    var openLogs = new ToolStripMenuItem("Open Logs Folder");
    var exit = new ToolStripMenuItem("Exit UI");

    _toggleModeItem.Click += (_, _) => ToggleModeWithConfirm();
    _lockNowItem.Click += (_, _) => EnableKillSwitchWithConfirm();
    _restoreItem.Click += (_, _) => RestoreKillSwitchWithConfirm();
    InitScanMenu();
    _lastIncidentItem.Click += (_, _) => ShowLastIncident();
    openLogs.Click += (_, _) => OpenLogsFolder();
    exit.Click += (_, _) => ExitThread();

    var menu = new ContextMenuStrip();
    menu.Items.Add(_statusItem);
    menu.Items.Add(_modeItem);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(_lockNowItem);
    menu.Items.Add(_restoreItem);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(_scanMenu);
    menu.Items.Add(_toggleModeItem);
    menu.Items.Add(_lastIncidentItem);
    menu.Items.Add(openLogs);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(exit);

    _notifyIcon = new NotifyIcon
    {
      Text = "AI Defender",
      Icon = IconFactory.CreateTrayIcon(),
      ContextMenuStrip = menu,
      Visible = true
    };
    _currentIcon = _notifyIcon.Icon;
    _notifyIcon.DoubleClick += (_, _) => ShowLastIncident();

    _timer = new System.Windows.Forms.Timer { Interval = 5_000 };
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
    var service = GetServiceState();
    var cfg = AgentFiles.TryReadConfig();
    var kill = AgentFiles.TryReadKillSwitchState();
    var last = AgentFiles.TryReadLastIncidentSummary();
    var versionWarning = CheckVersionMismatch();

    string status;
    var badge = IconFactory.Badge.Gray;
    if (service == ServiceControllerStatus.Running)
    {
      if (kill?.Enabled == true)
      {
        status = "🔴 Network Locked";
        badge = IconFactory.Badge.Red;
      }
      else if (cfg?.Mode == AgentMode.Learning)
      {
        if (last is not null && string.Equals(last.Severity, "yellow", StringComparison.OrdinalIgnoreCase)
            && IsRecent(last.CreatedAtUnixMs, minutes: 30))
        {
          status = "🟡 Learning Mode — Monitoring Only (warnings)";
          badge = IconFactory.Badge.Yellow;
        }
        else
        {
          status = "🟢 Learning Mode — Monitoring Only";
          badge = IconFactory.Badge.Green;
        }
      }
      else if (cfg?.Mode == AgentMode.Strict)
      {
        status = "🟢 Protected (Strict)";
        badge = IconFactory.Badge.Green;
      }
      else
      {
        status = "🟡 Learning Mode — Monitoring Only";
        badge = IconFactory.Badge.Yellow;
      }
    }
    else
    {
      status = "⚠️ Agent Not Running";
      badge = IconFactory.Badge.Gray;
    }

    _statusItem.Text = $"Status: {status}";
    _modeItem.Text = cfg is null ? "Mode: (unknown)" : $"Mode: {cfg.Mode}";
    if (!string.IsNullOrWhiteSpace(versionWarning))
    {
      _modeItem.Text += $"  ⚠ {versionWarning}";
    }

    // Keep tooltip short (Windows limits NotifyIcon.Text).
    _notifyIcon.Text = status.Length > 60 ? status[..60] : status;

    // Enable/disable menu items based on reachability.
    var agentReachable = service == ServiceControllerStatus.Running;
    _lockNowItem.Enabled = agentReachable;
    _restoreItem.Enabled = agentReachable;
    _scanMenu.Enabled = true;
    _toggleModeItem.Enabled = cfg is not null;
    _lastIncidentItem.Enabled = true;

    SetIconBadge(badge);
  }

  private static string? CheckVersionMismatch()
  {
    try
    {
      var agent = AgentCli.TryGetVersion();
      if (agent is null)
      {
        return null;
      }
      if (!string.Equals(agent, ProductInfo.Version, StringComparison.OrdinalIgnoreCase))
      {
        return $"version mismatch (UI {ProductInfo.Version} / Agent {agent})";
      }
      return null;
    }
    catch
    {
      return null;
    }
  }

  private void InitScanMenu()
  {
    var quick = new ToolStripMenuItem("Quick Scan…");
    var full = new ToolStripMenuItem("Full Scan…");
    quick.Click += (_, _) => StartScan(ScanMode.Quick);
    full.Click += (_, _) => StartScan(ScanMode.Full);
    _scanMenu.DropDownItems.Add(quick);
    _scanMenu.DropDownItems.Add(full);
  }

  private void StartScan(ScanMode mode)
  {
    var title = mode == ScanMode.Quick ? "AI Defender — Quick Scan" : "AI Defender — Full Scan";
    var msg =
      "Scanning is on-demand and runs at low priority.\n\n" +
      "Scanner findings alone never lock the network.\n\n" +
      "Start scan now?";
    if (MessageBox.Show(msg, title, MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes)
    {
      return;
    }

    using var dlg = new ScanProgressDialog(mode);
    dlg.ShowDialog();
  }

  private static bool IsRecent(ulong unixMs, int minutes)
  {
    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    if (unixMs == 0)
    {
      return false;
    }
    var delta = now - (long)unixMs;
    return delta >= 0 && delta <= minutes * 60_000L;
  }

  private void SetIconBadge(IconFactory.Badge badge)
  {
    var newIcon = IconFactory.CreateTrayIcon(badge);
    var old = _currentIcon;
    _notifyIcon.Icon = newIcon;
    _currentIcon = newIcon;
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
    var title = "AI Defender — Change Mode";
    var body =
      $"Current mode: {cfg.Mode}\n\n" +
      $"Switch to: {next}\n\n" +
      "Learning mode is the default and never auto-triggers network blocking.\n" +
      "Strict mode is opt-in and only auto-responds to RED incidents.\n\n" +
      "Proceed?";

    if (MessageBox.Show(body, title, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
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
      "AI Defender — Restart Service",
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
        "You can restart it from the Services app (services.msc) or reboot.",
        "AI Defender",
        MessageBoxButtons.OK,
        MessageBoxIcon.Information);
    }
  }

  private void EnableKillSwitchWithConfirm()
  {
    var msg =
      "This will block ALL inbound and outbound network traffic on this machine using Windows Firewall.\n\n" +
      "Proceed?";
    var res = MessageBox.Show(msg, "AI Defender — Enable Kill Switch", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
    if (res != DialogResult.Yes)
    {
      return;
    }

    var r = AgentCli.Run("--console", "--killswitch", "on");
    if (!r.Success)
    {
      MessageBox.Show(
        r.UserMessage,
        "AI Defender — Action Failed",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    RefreshStatus();
    MessageBox.Show(
      "Network locked. You can restore networking via the tray menu or the recovery instructions in docs.",
      "AI Defender — Network Locked",
      MessageBoxButtons.OK,
      MessageBoxIcon.Information);
  }

  private void RestoreKillSwitchWithConfirm()
  {
    var res = MessageBox.Show(
      "Restore network access by disabling the AI Defender kill switch rules?",
      "AI Defender — Restore Network",
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
        "AI Defender — Action Failed",
        MessageBoxButtons.OK,
        MessageBoxIcon.Error);
      return;
    }

    RefreshStatus();
    MessageBox.Show(
      "Networking should be restored.",
      "AI Defender — Network Restored",
      MessageBoxButtons.OK,
      MessageBoxIcon.Information);
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
