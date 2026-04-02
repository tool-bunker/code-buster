class Clients {
  public static HttpClient Shared { get; } = new HttpClient();
  private static readonly HttpClient Cached = new HttpClient();
  private readonly HttpClient AssignedOnce;
  private HttpClient Replaceable;
  Clients() {
    AssignedOnce = new HttpClient();
    Replaceable = new HttpClient();
  }
  void Fetch() {
    using (var client = new HttpClient()) {}
  }
}
