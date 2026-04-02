String unsafe(Map<String, String> values, String key) => values[key]!;

List<int> safe(Map<String, String> values) {
  final output = <int>[];
  for (final key in values.keys.toList()..sort()) {
    output.add(values[key]!.length);
  }
  return output;
}
