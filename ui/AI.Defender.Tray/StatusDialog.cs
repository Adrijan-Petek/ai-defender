using System.ServiceProcess;

namespace AI.Defender.Tray;

internal sealed class StatusDialog : Form
{
  public StatusDialog(AgentStatusSnapshot snapshot)
  {
    Text = "AI Defender - Status";
    Icon = IconFactory.CreateWindowIcon();
    StartPosition = FormStartPosition.CenterScreen;
    FormBorderStyle = FormBorderStyle.FixedDialog;
    MaximizeBox = false;
    MinimizeBox = false;
    ShowInTaskbar = false;
    Width = 520;
    Height = 320;

    var panel = new TableLayoutPanel
    {
      Dock = DockStyle.Fill,
      ColumnCount = 1,
      RowCount = 2,
      Padding = new Padding(12)
    };

    var content = new TextBox
    {
      Multiline = true,
      ReadOnly = true,
      ScrollBars = ScrollBars.Vertical,
      Dock = DockStyle.Fill,
      Font = new System.Drawing.Font("Segoe UI", 9F),
      Text = Format(snapshot)
    };

    var close = new Button
    {
      Text = "Close",
      Anchor = AnchorStyles.Right,
      DialogResult = DialogResult.OK
    };

    var buttons = new FlowLayoutPanel
    {
      Dock = DockStyle.Fill,
      FlowDirection = FlowDirection.RightToLeft,
      AutoSize = true
    };
    buttons.Controls.Add(close);

    panel.Controls.Add(content, 0, 0);
    panel.Controls.Add(buttons, 0, 1);
    panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
    panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

    Controls.Add(panel);
    AcceptButton = close;
  }

  private static string Format(AgentStatusSnapshot s)
  {
    var uiVersion = ProductInfo.Version;
    var agentVersion = AgentCli.TryGetVersion();
    var versionLine = agentVersion is null
      ? $"Versions: UI {uiVersion} / Agent (unknown)"
      : $"Versions: UI {uiVersion} / Agent {agentVersion}";

    if (agentVersion is not null && !string.Equals(agentVersion, uiVersion, StringComparison.OrdinalIgnoreCase))
    {
      versionLine += " (mismatch)";
    }

    var mode = s.Mode == AgentMode.Unknown ? "(unknown)" : s.Mode.ToString();
    var kill = s.KillSwitchEnabled ? "Enabled (network locked)" : "Disabled";

    var last = s.LastIncidentSummary is null
      ? "None"
      : FormatIncidentOneLine(s.LastIncidentSummary);

    var lic = AgentFiles.TryReadLicenseState();
    var licLine = lic is null
      ? "License: (unknown)"
      : lic.Pro
        ? $"License: Pro  (plan={lic.Plan ?? "unknown"})"
        : "License: Community";

    var licExpiry = lic?.ExpiresAtUnixMs is null
      ? null
      : $"License expiry: {TryFormatLocalTime(lic.ExpiresAtUnixMs.Value) ?? $"unix_ms={lic.ExpiresAtUnixMs.Value}"}";

    var feed = AgentFiles.TryReadThreatFeedState();
    var feedLine = feed is null
      ? "Threat feed: (unknown)"
      : !feed.Installed
        ? "Threat feed: not installed"
        : $"Threat feed: v{feed.Version?.ToString() ?? "unknown"}  (verified={(feed.Verified ? "yes" : "no")})";

    var stateLine = ComputeStateLine(s);

    var serviceDetail = string.IsNullOrWhiteSpace(s.ServiceDetail) ? null : $"Service: {s.ServiceDetail}";

    var lines = new List<string>
    {
      $"State: {stateLine}",
      $"Agent running: {(s.AgentRunning ? "Yes" : "No")}",
      $"Mode: {mode}",
      $"Kill switch: {kill}",
      licLine,
      feedLine,
      $"Last incident: {last}",
      versionLine,
    };

    if (licExpiry is not null)
    {
      lines.Add(licExpiry);
    }

    if (feed?.InstalledAtUnixMs is not null)
    {
      lines.Add(
        $"Threat feed updated: {TryFormatLocalTime(feed.InstalledAtUnixMs.Value) ?? $"unix_ms={feed.InstalledAtUnixMs.Value}"}");
    }
    if (feed?.LastVerifiedAtUnixMs is not null)
    {
      lines.Add(
        $"Threat feed last verified: {TryFormatLocalTime(feed.LastVerifiedAtUnixMs.Value) ?? $"unix_ms={feed.LastVerifiedAtUnixMs.Value}"}");
    }
    if (feed?.LastRefreshAttemptAtUnixMs is not null)
    {
      lines.Add(
        $"Threat feed last refresh attempt: {TryFormatLocalTime(feed.LastRefreshAttemptAtUnixMs.Value) ?? $"unix_ms={feed.LastRefreshAttemptAtUnixMs.Value}"}");
    }
    if (!string.IsNullOrWhiteSpace(feed?.LastRefreshResult))
    {
      lines.Add($"Threat feed last refresh result: {feed.LastRefreshResult}");
    }

    if (serviceDetail is not null)
    {
      lines.Add(serviceDetail);
    }

    lines.Add("");
    lines.Add("Note: The UI never shows raw logs or sensitive data.");

    return string.Join("\r\n", lines);
  }

  private static string ComputeStateLine(AgentStatusSnapshot s)
  {
    if (s.ServiceState is ServiceControllerStatus.StartPending
      or ServiceControllerStatus.StopPending
      or ServiceControllerStatus.ContinuePending
      or ServiceControllerStatus.PausePending)
    {
      return "Agent Service Restarting";
    }

    if (!s.AgentRunning)
    {
      return "Agent Not Running";
    }

    if (s.KillSwitchEnabled)
    {
      return "Network Locked - Kill Switch Active";
    }

    var mode = s.Mode == AgentMode.Unknown ? AgentMode.Learning : s.Mode;
    return mode == AgentMode.Strict
      ? "Strict Mode - Auto Response Enabled"
      : "Learning Mode - Monitoring Only";
  }

  private static string FormatIncidentOneLine(IncidentSummary inc)
  {
    var ts = TryFormatLocalTime(inc.CreatedAtUnixMs);
    var time = ts is null ? $"unix_ms={inc.CreatedAtUnixMs}" : ts;
    return $"{inc.IncidentId} severity={inc.Severity} time={time}";
  }

  private static string? TryFormatLocalTime(ulong unixMs)
  {
    try
    {
      if (unixMs == 0 || unixMs > long.MaxValue)
      {
        return null;
      }
      var dto = DateTimeOffset.FromUnixTimeMilliseconds((long)unixMs).ToLocalTime();
      return dto.ToString("yyyy-MM-dd HH:mm:ss zzz");
    }
    catch
    {
      return null;
    }
  }
}
