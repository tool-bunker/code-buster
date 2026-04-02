class HttpClient {
  static HttpClient? _instance;

  static HttpClient get instance {
    _instance ??= HttpClient();
    return _instance!;
  }
}

class ApiService {
  final HttpClient _client = HttpClient();
}
