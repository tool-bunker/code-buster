class Fallbacks {
  /// Reads a cache entry, returning null when it cannot be reused.
  Object? readCache() {
    try {
      return decodeCache();
    } on Object {
      return null;
    }
  }

  int? parseWidth(String source) {
    try {
      return int.parse(source);
    } on FormatException {
      return null;
    }
  }
}

int? parseTopLevel(String source) {
  try {
    return int.parse(source);
  } on FormatException {
    return null;
  }
}
