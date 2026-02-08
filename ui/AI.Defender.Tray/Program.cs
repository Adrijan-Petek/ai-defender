using System.Threading;

namespace AI.Defender.Tray;

internal static class Program
{
  [STAThread]
  private static void Main()
  {
    using var single = new Mutex(initiallyOwned: true, name: "AI_DEFENDER_TRAY_SINGLE_INSTANCE", out var isNew);
    if (!isNew)
    {
      return;
    }

    ApplicationConfiguration.Initialize();
    Application.Run(new TrayAppContext());
  }
}

