// Odin packages are directory based, so local imports and brace-delimited procedures need a focused adapter.

import 'package:path/path.dart' as path;

import '../../core/regexp_cache.dart';
import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Extracts local Odin package imports and procedure bodies.
final class OdinAdapter {
  /// Resolves relative package imports to every discovered file in that package.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Map<String, List<String>> filesByDirectory = <String, List<String>>{};
    for (final String sourcePath in sources.keys) {
      filesByDirectory
          .putIfAbsent(path.posix.dirname(sourcePath), () => <String>[])
          .add(sourcePath);
    }

    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      final Set<String> dependencies = <String>{};
      final String structure = _odinStructure(entry.value, maskStrings: false);
      for (final RegExpMatch match in _import.allMatches(structure)) {
        final String imported = match.requiredGroup(1);
        if (imported.contains(':')) continue;
        final String directory = path.posix.normalize(
          path.posix.join(path.posix.dirname(entry.key), imported),
        );
        for (final String candidate
            in filesByDirectory[directory] ?? const <String>[]) {
          if (candidate != entry.key) dependencies.add(candidate);
        }
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts named Odin procedures for shared complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final String structure = _odinStructure(entry.value);
      for (final RegExpMatch match in _procedure.allMatches(structure)) {
        final int opening = structure.indexOf('{', match.start);
        if (opening < 0) continue;
        final int closing = _matchingBrace(structure, opening);
        if (closing < 0) continue;
        result.add(
          FunctionSource(
            path: entry.key,
            name: match.group(1)!,
            line: _lineAt(entry.value, match.start),
            source: entry.value.substring(match.start, closing + 1),
          ),
        );
      }
    }
    return result;
  }

  static final RegExp _import = RegExp(
    r'^[ \t]*import[ \t]+(?:[A-Za-z_][\w]*|_|\.)?[ \t]*"([^"]+)"',
    multiLine: true,
  );
  static final RegExp _procedure = RegExp(
    r'^[ \t]*([A-Za-z_]\w*)[ \t]*::[ \t]*proc(?:[ \t]+"[^"]+")?[ \t]*\([^;{}]*\)[^{;]*\{',
    multiLine: true,
  );
}

int _matchingBrace(String source, int opening) {
  var depth = 0;
  for (var index = opening; index < source.length; index++) {
    if (source[index] == '{') {
      depth++;
    } else if (source[index] == '}' && --depth == 0) {
      return index;
    }
  }
  return -1;
}

int _lineAt(String source, int offset) =>
    1 + '\n'.allMatches(source.substring(0, offset)).length;

String _odinStructure(String source, {bool maskStrings = true}) {
  final StringBuffer result = StringBuffer();
  var blockDepth = 0;
  var lineComment = false;
  String? quote;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    if (lineComment) {
      if (character == '\n') {
        lineComment = false;
        result.write('\n');
      } else {
        result.write(' ');
      }
      continue;
    }
    if (blockDepth > 0) {
      result.write(character == '\n' ? '\n' : ' ');
      if (character == '/' && next == '*') {
        blockDepth++;
        result.write(' ');
        index++;
      } else if (character == '*' && next == '/') {
        blockDepth--;
        result.write(' ');
        index++;
      }
      continue;
    }
    if (quote != null) {
      result.write(maskStrings ? (character == '\n' ? '\n' : ' ') : character);
      if (quote != '`' && character == r'\' && next.isNotEmpty) {
        result.write(maskStrings ? (next == '\n' ? '\n' : ' ') : next);
        index++;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == '/' && next == '/') {
      lineComment = true;
      result.write('  ');
      index++;
    } else if (character == '/' && next == '*') {
      blockDepth = 1;
      result.write('  ');
      index++;
    } else if (character == '"' || character == "'" || character == '`') {
      quote = character;
      result.write(maskStrings ? ' ' : character);
    } else {
      result.write(character);
    }
  }
  return result.toString();
}
