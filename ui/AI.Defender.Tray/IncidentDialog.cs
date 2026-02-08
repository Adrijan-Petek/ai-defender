namespace AI.Defender.Tray;

internal sealed class IncidentDialog : Form
{
  public IncidentDialog(IncidentSummary? summary)
  {
    Text = "AI Defender — Last Incident";
    Icon = IconFactory.CreateWindowIcon();
    StartPosition = FormStartPosition.CenterScreen;
    FormBorderStyle = FormBorderStyle.FixedDialog;
    MaximizeBox = false;
    MinimizeBox = false;
    ShowInTaskbar = false;
    Width = 520;
    Height = 340;

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
    };

    content.Text = summary is null ? "No incidents found." : Format(summary);

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

  private static string Format(IncidentSummary s)
  {
    var rules = s.RuleIds.Count == 0 ? "(none)" : string.Join(", ", s.RuleIds);
    var actions = s.ActionsTaken.Count == 0 ? "(none)" : string.Join(", ", s.ActionsTaken);

    return
      $"Incident ID: {s.IncidentId}\r\n" +
      $"Severity: {s.Severity}\r\n" +
      $"Created (unix ms): {s.CreatedAtUnixMs}\r\n" +
      $"Rules triggered: {rules}\r\n" +
      $"Actions taken: {actions}\r\n\r\n" +
      "Note: AI Defender never displays file contents, clipboard contents, or secrets.";
  }
}

