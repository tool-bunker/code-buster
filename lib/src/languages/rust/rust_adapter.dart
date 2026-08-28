// Rust modules and functions need a lightweight repository index before cross-file and complexity checks can reason about them.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Extracts local Rust module edges and brace-delimited functions.
final class RustAdapter {
  /// Resolves `mod` declarations and local `use` paths to discovered Rust files.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Set<String> known = sources.keys.toSet();
    final Map<String, List<String>> byStem = <String, List<String>>{};
    for (final String sourcePath in known) {
      byStem.putIfAbsent(_stem(sourcePath), () => <String>[]).add(sourcePath);
    }

    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      final String code = _rustStructure(entry.value);
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch declaration in _module.allMatches(code)) {
        final String module = declaration.group(1)!;
        final String directory = path.posix.dirname(entry.key);
        for (final String candidate in <String>[
          path.posix.join(directory, '$module.rs'),
          path.posix.join(directory, module, 'mod.rs'),
        ]) {
          if (known.contains(candidate)) dependencies.add(candidate);
        }
      }
      for (final RegExpMatch import in _use.allMatches(code)) {
        final String module = import.group(1)!;
        final List<String> owners = byStem[module] ?? const <String>[];
        if (owners.length == 1 && owners.single != entry.key) {
          dependencies.add(owners.single);
        }
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts Rust functions for language-neutral complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final String code = _rustStructure(entry.value);
      final Set<int> testLines = rustCfgTestLines(code.split('\n'));
      for (final RegExpMatch match in _function.allMatches(code)) {
        final int declarationStart =
            match.start + RegExp(r'\bfn\s+').firstMatch(match.group(0)!)!.start;
        final int open = code.indexOf('{', match.start);
        final int close = _matchingBrace(code, open);
        if (testLines.contains(_lineAt(code, declarationStart) - 1)) continue;
        if (open == -1 || close == -1) continue;
        result.add(
          FunctionSource(
            path: entry.key,
            name: match.group(1)!,
            line: _lineAt(entry.value, declarationStart),
            source: entry.value.substring(declarationStart, close + 1),
          ),
        );
      }
    }
    return result;
  }

  static String _stem(String sourcePath) {
    final String name = path.posix.basenameWithoutExtension(sourcePath);
    return name == 'mod'
        ? path.posix.basename(path.posix.dirname(sourcePath))
        : name;
  }

  static final RegExp _module = RegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;',
    multiLine: true,
  );
  static final RegExp _use = RegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:(?:crate|self|super)::)*([A-Za-z_]\w*)',
    multiLine: true,
  );
  static final RegExp _function = RegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\([^;{}]*\)[^{;]*\{',
    multiLine: true,
  );
}

/// Returns zero-based lines controlled by a `cfg` predicate containing `test`.
Set<int> rustCfgTestLines(List<String> lines) => _rustAttributedLines(
  lines,
  (String line) =>
      RegExp(r'#\s*\[\s*cfg\s*\([^\n]*test[^\n]*\)\s*\]').hasMatch(line),
);

Set<int> _rustAttributedLines(
  List<String> lines,
  bool Function(String line) matchesAttribute,
) {
  final Set<int> result = <int>{};
  var pending = false;
  var excludedDepth = 0;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    if (excludedDepth > 0) {
      result.add(index);
      excludedDepth +=
          '{'.allMatches(line).length - '}'.allMatches(line).length;
      continue;
    }
    if (matchesAttribute(line)) {
      pending = true;
      result.add(index);
      continue;
    }
    if (pending && line.trimLeft().startsWith('#[')) {
      result.add(index);
      continue;
    }
    if (pending && line.trim().isNotEmpty) {
      result.add(index);
      excludedDepth = '{'.allMatches(line).length - '}'.allMatches(line).length;
      pending = false;
    }
  }
  return result;
}

int _matchingBrace(String source, int open) {
  if (open < 0) return -1;
  var depth = 0;
  String? quote;
  for (var index = open; index < source.length; index++) {
    final String character = source[index];
    if (quote != null) {
      if (character == r'\' && index + 1 < source.length) {
        index++;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == '"') {
      quote = character;
    } else if (character == "'" &&
        index + 2 < source.length &&
        source[index + 2] == "'") {
      index += 2;
    } else if (character == "'" &&
        index + 3 < source.length &&
        source[index + 1] == r'\' &&
        source[index + 3] == "'") {
      index += 3;
    } else if (character == '{') {
      depth++;
    } else if (character == '}' && --depth == 0) {
      return index;
    }
  }
  return -1;
}

String _rustStructure(String source) {
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
      result.write(character == '\n' ? '\n' : ' ');
      if (character == r'\' && next.isNotEmpty) {
        result.write(next == '\n' ? '\n' : ' ');
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
    } else if (character == '"') {
      quote = character;
      result.write(' ');
    } else if (character == "'" &&
        index + 2 < source.length &&
        source[index + 2] == "'") {
      result.write('   ');
      index += 2;
    } else if (character == "'" &&
        index + 3 < source.length &&
        source[index + 1] == r'\' &&
        source[index + 3] == "'") {
      result.write('    ');
      index += 3;
    } else {
      result.write(character);
    }
  }
  return result.toString();
}

int _lineAt(String source, int offset) =>
    1 + '\n'.allMatches(source.substring(0, offset)).length;
