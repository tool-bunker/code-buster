Future<void> run(final Object session, {
  required final String id,
  final int limit = 10,
  @deprecated final String? legacy,
  final void Function()? callback,
}) async {
  consume([final int amount = 10]) => amount;
  stream.listen((var message) => print(message));
  items.forEach((var entity) => print(entity));
  final entries = <String, String>{}.entries;
  for (final MapEntry(key: key, value: value) in entries) {
    print(key + value);
  }
}