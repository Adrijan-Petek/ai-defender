using System.Drawing;
using System.Runtime.InteropServices;

namespace AI.Defender.Tray;

internal static class IconFactory
{
  internal enum Badge
  {
    None = 0,
    Green,
    Yellow,
    Red,
    Gray
  }

  public static Icon CreateTrayIcon(Badge badge = Badge.None)
  {
    using var bmp = LoadLogoBitmapWithBadge(64, badge);
    var hIcon = bmp.GetHicon();
    try
    {
      // Clone so we can release the HICON immediately without invalidating the returned Icon.
      return (Icon)Icon.FromHandle(hIcon).Clone();
    }
    finally
    {
      // Ensure we release the GDI handle to avoid leaks.
      DestroyIcon(hIcon);
    }
  }

  public static Icon CreateWindowIcon()
  {
    using var bmp = LoadLogoBitmapWithBadge(48, Badge.None);
    var hIcon = bmp.GetHicon();
    try
    {
      return (Icon)Icon.FromHandle(hIcon).Clone();
    }
    finally
    {
      DestroyIcon(hIcon);
    }
  }

  private static Bitmap LoadLogoBitmapWithBadge(int size, Badge badge)
  {
    var asm = typeof(IconFactory).Assembly;
    var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("Resources.ai-defender.png", StringComparison.OrdinalIgnoreCase));
    if (name is null)
    {
      // Fallback: create a blank bitmap to avoid crashes. This should not happen in a normal build.
      return new Bitmap(size, size);
    }

    using var stream = asm.GetManifestResourceStream(name)!;
    using var original = new Bitmap(stream);
    var scaled = new Bitmap(original, new Size(size, size));
    if (badge == Badge.None)
    {
      return scaled;
    }

    using var g = Graphics.FromImage(scaled);
    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

    var color = badge switch
    {
      Badge.Green => Color.FromArgb(0x23, 0xC5, 0x5E),
      Badge.Yellow => Color.FromArgb(0xF5, 0xC5, 0x18),
      Badge.Red => Color.FromArgb(0xE5, 0x3E, 0x3E),
      _ => Color.FromArgb(0x9A, 0x9A, 0x9A)
    };

    var diameter = Math.Max(10, size / 5);
    var pad = Math.Max(2, size / 16);
    var x = size - diameter - pad;
    var y = size - diameter - pad;

    using var bg = new SolidBrush(Color.FromArgb(220, Color.White));
    using var dot = new SolidBrush(color);
    g.FillEllipse(bg, x - 1, y - 1, diameter + 2, diameter + 2);
    g.FillEllipse(dot, x, y, diameter, diameter);

    return scaled;
  }

  [DllImport("user32.dll", SetLastError = true)]
  private static extern bool DestroyIcon(IntPtr hIcon);
}
