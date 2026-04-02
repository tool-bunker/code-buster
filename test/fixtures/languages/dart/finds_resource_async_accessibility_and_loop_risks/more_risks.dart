class MoreRisks {
  ReceivePort? port = ReceivePort();
  RandomAccessFile? file = openFile();

  Future<String> load(File source) async => source.readAsStringSync();

  Widget build(BuildContext context) => Column(children: [
    ListView(children: const []),
    Listener(onPointerUp: activate, child: const Text('Run')),
  ]);

  String scan(List<String> items) {
    String output = '';
    for (final item in items) {
      final matcher = RegExp('item');
      output += item;
    }
    items.any(valid);
    items.firstWhere(valid);
    items.contains('done');
    return output;
  }
}
