public static class PublicNative {
  [DllImport("kernel32.dll")]
  public static extern bool PublicCall();
}

internal static class InternalNative {
  [DllImport("kernel32.dll")]
  public static extern bool InternalCall();
}

static class PackageNative {
  [LibraryImport("kernel32.dll")]
  public static partial bool PackageCall();
}

public class PublicApi {
  private static class NestedNative {
    [DllImport("kernel32.dll")]
    public static extern bool NestedCall();
  }

  public static class PublicNestedNative {
    [LibraryImport("kernel32.dll")]
    public static partial bool PublicNestedCall();
  }

  protected static class ProtectedNestedNative {
    [DllImport("kernel32.dll")]
    public static extern bool ProtectedNestedCall();
  }
}
