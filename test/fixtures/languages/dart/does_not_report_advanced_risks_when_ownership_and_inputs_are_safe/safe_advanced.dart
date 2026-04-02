class SafeState {
  final TextEditingController _controller = TextEditingController();
  Timer? _timer;
  final source = Source();
  late final Future<Result> _future;
  final IOSink _sink = openSink();
  final HttpClient _httpClient = HttpClient();
  Isolate? _worker;

  void initState() {
    _future = fetch();
    source.addListener(_changed);
  }

  Future<void> load() async {
    await fetch();
    if (!mounted) return;
    setState(() {});
    await db.rawQuery('SELECT * FROM users WHERE id = ?', <Object>[1]);
  }

  void handle() {
    try {
      decode();
    } catch (error, stackTrace) {
      logger.error(error, stackTrace);
      rethrow;
    }
  }

  Widget build(BuildContext context) =>
      FutureBuilder(future: _future, builder: buildResult);

  void dispose() {
    source
      ..removeListener(_changed);
    _timer?.cancel();
    _controller.dispose();
    _worker?.kill();
    _httpClient.close();
    _sink.close();
    super.dispose();
  }

  Widget dismissBarrier() => GestureDetector(
    onTap: () {},
    child: const ColoredBox(color: Colors.black),
  );
}

class _OverlayScrim {
  final VoidCallback onTap;
  Widget build() => GestureDetector(onTap: onTap);
}
