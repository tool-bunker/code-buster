void scan(String raw, List<String> values) {
  for (final part in raw.split(RegExp(r'[;,]'))) {
    consume(part);
  }
  for (final value in values) {
    if (RegExp(r'^\w+$').hasMatch(value)) {
      consume(value);
    }
  }
}
