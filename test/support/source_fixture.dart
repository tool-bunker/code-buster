import 'dart:io';

import 'package:path/path.dart' as path;

const String _fixtureRoot = 'test/fixtures/languages';

/// Loads source exactly as stored; fixtures may intentionally be malformed or
/// poorly formatted when that is the behavior under test.
String sourceFixture(String relativePath) {
  final String normalized = path.normalize(relativePath);
  if (path.isAbsolute(normalized) ||
      normalized == '..' ||
      normalized.startsWith('../')) {
    throw ArgumentError.value(relativePath, 'relativePath');
  }
  return File(path.join(_fixtureRoot, normalized)).readAsStringSync();
}
