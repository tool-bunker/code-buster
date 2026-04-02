class MoreSafe {
  ReceivePort? port;
  RandomAccessFile? file;
  final RegExp matcher = RegExp('item');

  Future<String> load(File source) async => source.readAsString();

  Widget build(BuildContext context) => Column(children: [
    Expanded(child: ListView(children: const [])),
    Semantics(
      button: true,
      child: GestureDetector(onTap: activate, child: const Text('Run')),
    ),
    Listener(
      onPointerDown: track,
      onPointerMove: track,
      onPointerUp: track,
      child: const Text('Tracked region'),
    ),
  ]);

  String scan(List<String> items) {
    final buffer = StringBuffer();
    for (final item in items) {
      if (matcher.hasMatch(item)) buffer.write(item);
    }
    return buffer.toString();
  }

  bool matchesAny(List<String> patterns, String value) {
    for (final pattern in patterns) {
      if (RegExp(pattern).hasMatch(value)) return true;
    }
    return false;
  }

  bool containsKnownValues(Set<String> values) =>
      values.contains('alpha') ||
      values.contains('beta') ||
      values.contains('gamma');

  bool hasKnownPrefix(String line) =>
      line.contains('http:') ||
      line.contains('https:') ||
      line.contains('file:');

  void dispose() {
    port?.close();
    file?.close();
  }
}
