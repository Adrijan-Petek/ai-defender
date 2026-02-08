namespace AI.Defender.Tray;

internal sealed class ScanProgressDialog : Form
{
  private readonly ScanMode _mode;
  private readonly TextBox _log;
  private readonly ProgressBar _bar;
  private readonly Button _cancel;
  private readonly Button _close;
  private ScannerCli? _cli;

  public ScanProgressDialog(ScanMode mode)
  {
    _mode = mode;

    Text = mode == ScanMode.Quick ? "AI Defender — Quick Scan" : "AI Defender — Full Scan";
    Icon = IconFactory.CreateWindowIcon();
    StartPosition = FormStartPosition.CenterScreen;
    FormBorderStyle = FormBorderStyle.FixedDialog;
    MaximizeBox = false;
    MinimizeBox = false;
    ShowInTaskbar = false;
    Width = 640;
    Height = 420;

    _bar = new ProgressBar
    {
      Dock = DockStyle.Top,
      Height = 18,
      Style = ProgressBarStyle.Marquee
    };

    _log = new TextBox
    {
      Multiline = true,
      ReadOnly = true,
      Dock = DockStyle.Fill,
      ScrollBars = ScrollBars.Vertical,
      Font = new System.Drawing.Font("Segoe UI", 9F)
    };

    _cancel = new Button { Text = "Cancel", AutoSize = true };
    _close = new Button { Text = "Close", AutoSize = true, Enabled = false };
    _cancel.Click += (_, _) => CancelScan();
    _close.Click += (_, _) => Close();

    var buttons = new FlowLayoutPanel
    {
      Dock = DockStyle.Bottom,
      FlowDirection = FlowDirection.RightToLeft,
      Padding = new Padding(12),
      AutoSize = true
    };
    buttons.Controls.Add(_close);
    buttons.Controls.Add(_cancel);

    Controls.Add(_log);
    Controls.Add(_bar);
    Controls.Add(buttons);

    Shown += (_, _) => Start();
  }

  private void Start()
  {
    var r = ScannerCli.Start(_mode);
    if (!r.Success || r.Cli is null)
    {
      MessageBox.Show(r.UserMessage, "AI Defender — Scan Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
      _close.Enabled = true;
      _cancel.Enabled = false;
      _bar.Style = ProgressBarStyle.Continuous;
      _bar.Value = 0;
      return;
    }

    _cli = r.Cli;
    Append($"Scanner started: mode={_mode}");

    _cli.Process.OutputDataReceived += (_, e) =>
    {
      if (string.IsNullOrWhiteSpace(e.Data)) return;
      BeginInvoke(() => Append(e.Data!));
    };
    _cli.Process.ErrorDataReceived += (_, e) =>
    {
      if (string.IsNullOrWhiteSpace(e.Data)) return;
      BeginInvoke(() => Append(e.Data!));
    };

    _cli.Process.EnableRaisingEvents = true;
    _cli.Process.Exited += (_, _) => BeginInvoke(OnExited);

    _cli.Process.BeginOutputReadLine();
    _cli.Process.BeginErrorReadLine();
  }

  private void OnExited()
  {
    _bar.Style = ProgressBarStyle.Continuous;
    _bar.Value = 100;
    _cancel.Enabled = false;
    _close.Enabled = true;

    Append("Scan finished.");
    var last = AgentFiles.TryReadLastIncidentSummary();
    if (last is not null && string.Equals(last.Severity, "yellow", StringComparison.OrdinalIgnoreCase))
    {
      Append($"Latest incident: {last.IncidentId} severity={last.Severity} rules={string.Join(",", last.RuleIds)}");
    }
  }

  private void CancelScan()
  {
    if (_cli is null)
    {
      return;
    }
    _cli.RequestCancel();
    Append("Cancel requested…");
    _cancel.Enabled = false;
  }

  private void Append(string line)
  {
    var ts = DateTime.Now.ToString("HH:mm:ss");
    _log.AppendText($"[{ts}] {line}{Environment.NewLine}");
  }
}

