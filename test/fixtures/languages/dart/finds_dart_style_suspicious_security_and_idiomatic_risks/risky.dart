void run(dynamic input, String command) async {
	print(input);  
  late String value;
  final token = Random();
  try {
    Process.run(command, const [], runInShell: true);
  } catch (_) {}
}
