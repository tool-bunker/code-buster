// Python adapters and rules share source lines and lexical masking through this repository-local index.

import '../../core/models.dart';

/// Immutable source facts for one Python file.
final class PythonSourceFacts {
  /// Creates facts for [path] and [source].
  PythonSourceFacts({required this.path, required this.source})
    : lines = List<String>.unmodifiable(source.split('\n'));

  /// Project-relative source path.
  final String path;

  /// Original source text.
  final String source;

  /// Source split into stable lines once.
  final List<String> lines;

  /// Source with comments and string contents replaced by spaces.
  late final String maskedSource = _maskNonCode(source);
}

/// Shared per-file Python lexical facts, ordered by project-relative path.
final class PythonSourceIndex {
  /// Indexes [sources] once in deterministic path order.
  factory PythonSourceIndex(Map<String, String> sources) {
    final List<String> paths = sources.keys.toList(growable: false)..sort();
    return PythonSourceIndex._(
      List<PythonSourceFacts>.unmodifiable(
        paths.map(
          (String path) => PythonSourceFacts(
            path: path,
            source: sources.requiredValue(path),
          ),
        ),
      ),
    );
  }

  const PythonSourceIndex._(this.files);

  /// Indexed files in deterministic path order.
  final List<PythonSourceFacts> files;
}

String _maskNonCode(String source) {
  final List<int> result = source.codeUnits.toList();
  String? quote;
  var tripleQuoted = false;
  var escaped = false;
  var inComment = false;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    final String nextTwo = index + 2 < source.length
        ? source.substring(index, index + 3)
        : '';
    if (inComment) {
      if (character == '\n') {
        inComment = false;
      } else {
        result[index] = 0x20;
      }
      continue;
    }
    if (quote != null) {
      if (character != '\n' && character != '\r') result[index] = 0x20;
      if (tripleQuoted && nextTwo == quote * 3) {
        result[index + 1] = 0x20;
        result[index + 2] = 0x20;
        index += 2;
        quote = null;
        tripleQuoted = false;
      } else if (!tripleQuoted && !escaped && character == quote) {
        quote = null;
      }
      escaped = !tripleQuoted && !escaped && character == r'\';
      if (character != r'\') escaped = false;
      continue;
    }
    if (character == '#') {
      result[index] = 0x20;
      inComment = true;
    } else if (character == '"' || character == "'") {
      quote = character;
      tripleQuoted =
          next == character &&
          index + 2 < source.length &&
          source[index + 2] == character;
      result[index] = 0x20;
      if (tripleQuoted) {
        result[index + 1] = 0x20;
        result[index + 2] = 0x20;
        index += 2;
      }
    }
  }
  return String.fromCharCodes(result);
}
