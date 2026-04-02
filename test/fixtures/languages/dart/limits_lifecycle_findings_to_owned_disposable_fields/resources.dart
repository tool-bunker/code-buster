class HttpClient implements ClientContract {
  final MenuController _menuController = MenuController();
  WebViewController? _webViewController;
  Timer? _timer;

  void stopTimer() {
    _timer!.cancel();
  }
}
