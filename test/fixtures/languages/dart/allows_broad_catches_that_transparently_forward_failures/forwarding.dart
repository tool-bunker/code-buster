Future<void> save() async {
  try {
    await write();
  } catch (_) {
    rethrow;
  }
}

void complete(Completer<void> result) async {
  try {
    result.complete(await load());
  } catch (error, stack) {
    result.completeError(error, stack);
  }
}

void swallow() {
  try {
    parse();
  } catch (_) {}
}
