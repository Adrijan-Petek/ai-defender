namespace AI.Defender.Tray;

internal static class ProductInfo
{
  private const string DefaultName = "AI Defender";
  private const string DefaultServiceName = "AI_DEFENDER_AGENT";
  private const string DefaultVersion = "0.1.1-alpha";

  public static string Name => Load().Name;
  public static string ServiceName => Load().ServiceName;
  public static string Version => Load().Version;

  private static ProductIdentity? _cached;

  private static ProductIdentity Load()
  {
    if (_cached is not null)
    {
      return _cached;
    }

    var identity = new ProductIdentity(DefaultName, DefaultServiceName, DefaultVersion);
    try
    {
      var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "PRODUCT.toml"));
      if (File.Exists(path))
      {
        var text = File.ReadAllText(path);
        identity = Parse(text, identity);
      }
      else
      {
        var versionPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "VERSION"));
        if (File.Exists(versionPath))
        {
          var version = File.ReadAllText(versionPath).Trim();
          if (!string.IsNullOrWhiteSpace(version))
          {
            identity = identity with { Version = version };
          }
        }
      }
    }
    catch
    {
      // best-effort: keep defaults
    }

    _cached = identity;
    return identity;
  }

  private static ProductIdentity Parse(string text, ProductIdentity fallback)
  {
    string? name = null;
    string? service = null;
    string? version = null;

    foreach (var line in text.Split('\n'))
    {
      var t = line.Trim();
      if (t.Length == 0 || t.StartsWith("#", StringComparison.Ordinal))
      {
        continue;
      }
      var idx = t.IndexOf('=');
      if (idx <= 0)
      {
        continue;
      }
      var k = t[..idx].Trim();
      var v = t[(idx + 1)..].Trim().Trim('"');

      if (string.Equals(k, "name", StringComparison.OrdinalIgnoreCase)) name = v;
      if (string.Equals(k, "service_name", StringComparison.OrdinalIgnoreCase)) service = v;
      if (string.Equals(k, "version", StringComparison.OrdinalIgnoreCase)) version = v;
    }

    return new ProductIdentity(
      string.IsNullOrWhiteSpace(name) ? fallback.Name : name!,
      string.IsNullOrWhiteSpace(service) ? fallback.ServiceName : service!,
      string.IsNullOrWhiteSpace(version) ? fallback.Version : version!);
  }
}

internal sealed record ProductIdentity(string Name, string ServiceName, string Version);
