// JavaScript and TypeScript module forms vary widely, so this adapter normalizes their imports and function boundaries for shared analysis.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Extracts named JavaScript and TypeScript function bodies for shared metrics.
final class JavaScriptFunctionAnalysis {
  /// Returns named declarations, methods, and block-bodied arrow functions.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String sourcePath in paths) {
      final String source = sources[sourcePath]!;
      final String masked = _maskStringsAndComments(source);
      final Map<int, ({int start, String name})> candidates =
          <int, ({int start, String name})>{};
      for (final RegExp pattern in <RegExp>[
        _functionDeclaration,
        _blockMethod,
        _arrowFunction,
      ]) {
        for (final RegExpMatch match in pattern.allMatches(masked)) {
          final int brace = masked.indexOf('{', match.start);
          if (brace < 0 || brace >= match.end) continue;
          final String name = match.namedGroup('name') ?? '<anonymous>';
          if (_controlKeywords.contains(name)) continue;
          candidates.putIfAbsent(brace, () => (start: match.start, name: name));
        }
      }
      for (final RegExpMatch match in _blockArrowFunction.allMatches(masked)) {
        final int brace = masked.indexOf('{', match.start);
        if (brace < 0 || brace >= match.end) continue;
        candidates.putIfAbsent(
          brace,
          () => (start: match.start, name: '<anonymous>'),
        );
      }
      final List<int> braces = candidates.keys.toList()..sort();
      final Map<int, int> ends = <int, int>{
        for (final int brace in braces)
          if (_matchingBrace(masked, brace) case final int end when end >= 0)
            brace: end,
      };
      for (final int brace in braces) {
        final int? end = ends[brace];
        if (end == null) continue;
        final ({int start, String name}) candidate = candidates[brace]!;
        result.add(
          FunctionSource(
            path: sourcePath,
            name: candidate.name,
            line:
                '\n'.allMatches(source.substring(0, candidate.start)).length +
                1,
            source: _withoutNestedFunctions(
              source,
              start: candidate.start,
              opening: brace,
              end: end,
              candidates: candidates,
              ends: ends,
            ),
          ),
        );
      }
    }
    return result;
  }

  static final RegExp _functionDeclaration = RegExp(
    r'(?:(?:export\s+)?(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(?<name>[A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*\{',
    multiLine: true,
  );
  static final RegExp _blockMethod = RegExp(
    r'(?:(?:public|private|protected|static|abstract|override|readonly|async|get|set)\s+)*(?<name>[A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?\s*\([^();{}]*\)\s*(?::\s*[^={};]+)?\s*\{',
    multiLine: true,
  );
  static final RegExp _arrowFunction = RegExp(
    r'(?:const|let|var)\s+(?<name>[A-Za-z_$][\w$]*)\s*(?:\??\s*:\s*[^=]+)?=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=>\s*\{',
    multiLine: true,
  );
  static final RegExp _blockArrowFunction = RegExp(
    r'(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=>\s*\{',
    multiLine: true,
  );
  static const Set<String> _controlKeywords = <String>{
    'if',
    'for',
    'while',
    'switch',
    'catch',
    'with',
    'function',
  };

  static int _matchingBrace(String source, int opening) {
    var depth = 0;
    for (var index = opening; index < source.length; index++) {
      if (source.codeUnitAt(index) == 123) depth++;
      if (source.codeUnitAt(index) == 125 && --depth == 0) return index;
    }
    return -1;
  }

  static String _withoutNestedFunctions(
    String source, {
    required int start,
    required int opening,
    required int end,
    required Map<int, ({int start, String name})> candidates,
    required Map<int, int> ends,
  }) {
    final List<int> result = source
        .substring(start, end + 1)
        .codeUnits
        .toList();
    for (final int nestedOpening in candidates.keys) {
      final int? nestedEnd = ends[nestedOpening];
      if (nestedOpening <= opening || nestedEnd == null || nestedEnd > end) {
        continue;
      }
      final int nestedStart = candidates[nestedOpening]!.start;
      for (
        var index = nestedStart - start;
        index <= nestedEnd - start;
        index++
      ) {
        if (result[index] != 10) result[index] = 32;
      }
    }
    return String.fromCharCodes(result);
  }

  static String _maskStringsAndComments(String source) {
    final List<int> result = source.codeUnits.toList();
    var index = 0;
    while (index < result.length) {
      final int current = result[index];
      if (current == 47 &&
          index + 1 < result.length &&
          result[index + 1] == 47) {
        while (index < result.length && result[index] != 10) {
          result[index++] = 32;
        }
        continue;
      }
      if (current == 47 &&
          index + 1 < result.length &&
          result[index + 1] == 42) {
        result[index++] = 32;
        result[index++] = 32;
        while (index + 1 < result.length &&
            !(result[index] == 42 && result[index + 1] == 47)) {
          if (result[index] != 10) result[index] = 32;
          index++;
        }
        if (index + 1 < result.length) {
          result[index++] = 32;
          result[index++] = 32;
        }
        continue;
      }
      if (current == 47 && _startsRegexLiteral(source, index)) {
        var inCharacterClass = false;
        result[index++] = 32;
        while (index < result.length && result[index] != 10) {
          if (result[index] == 92) {
            result[index++] = 32;
            if (index < result.length && result[index] != 10) {
              result[index++] = 32;
            }
            continue;
          }
          if (result[index] == 91) inCharacterClass = true;
          if (result[index] == 93) inCharacterClass = false;
          if (result[index] == 47 && !inCharacterClass) {
            result[index++] = 32;
            while (index < result.length &&
                _isAsciiIdentifierPart(result[index])) {
              result[index++] = 32;
            }
            break;
          }
          result[index++] = 32;
        }
        continue;
      }
      if (current == 34 || current == 39 || current == 96) {
        final int quote = current;
        result[index++] = 32;
        while (index < result.length) {
          if (result[index] == 92) {
            result[index++] = 32;
            if (index < result.length && result[index] != 10) {
              result[index++] = 32;
            }
            continue;
          }
          if (result[index] == quote) {
            result[index++] = 32;
            break;
          }
          if (result[index] != 10) result[index] = 32;
          index++;
        }
        continue;
      }
      index++;
    }
    return String.fromCharCodes(result);
  }

  static bool _startsRegexLiteral(String source, int slash) {
    var index = slash - 1;
    while (index >= 0 && _isWhitespace(source.codeUnitAt(index))) {
      index--;
    }
    if (index < 0) return true;
    if (_canPrecedeRegex(source.codeUnitAt(index))) {
      return true;
    }
    if (!_isAsciiIdentifierPart(source.codeUnitAt(index))) return false;
    final int end = index + 1;
    while (index >= 0 && _isAsciiIdentifierPart(source.codeUnitAt(index))) {
      index--;
    }
    return const <String>{
      'await',
      'case',
      'delete',
      'in',
      'instanceof',
      'new',
      'of',
      'return',
      'throw',
      'typeof',
      'void',
      'yield',
    }.contains(source.substring(index + 1, end));
  }

  static bool _canPrecedeRegex(int codeUnit) => switch (codeUnit) {
    33 || // !
    37 || // %
    38 || // &
    40 || // (
    42 || // *
    43 || // +
    44 || // ,
    45 || // -
    58 || // :
    59 || // ;
    60 || // <
    61 || // =
    62 || // >
    63 || // ?
    91 || // [
    94 || // ^
    123 || // {
    124 || // |
    126 => true, // ~
    _ => false,
  };

  static bool _isWhitespace(int codeUnit) =>
      codeUnit == 9 || codeUnit == 10 || codeUnit == 13 || codeUnit == 32;

  static bool _isAsciiIdentifierPart(int codeUnit) =>
      (codeUnit >= 48 && codeUnit <= 57) ||
      (codeUnit >= 65 && codeUnit <= 90) ||
      codeUnit == 95 ||
      codeUnit == 36 ||
      (codeUnit >= 97 && codeUnit <= 122);
}

/// Resolves local ECMAScript, TypeScript, and CommonJS dependencies.
final class JavaScriptGraphAdapter {
  /// Builds a dependency graph from project-relative JavaScript-family [sources].
  DependencyGraph build(Map<String, String> sources) {
    final Set<String> knownFiles = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    final List<String> files = sources.keys.toList()..sort();
    for (final String sourcePath in files) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _specifierPattern.allMatches(
        sources[sourcePath]!,
      )) {
        final String? target = _resolve(
          sourcePath,
          match.group(1)!,
          knownFiles,
        );
        if (target != null) {
          dependencies.add(target);
        }
      }
      edges[sourcePath] = dependencies;
    }
    return DependencyGraph(edges);
  }

  static final RegExp _specifierPattern = RegExp(
    r'''(?:import\s+(?!type\b)(?:[^;'"\n]*?\s+from\s+)?|export\s+(?!type\b)[^;'"\n]*?\s+from\s+|require\s*\()\s*['"]([^'"]+)['"]''',
  );

  String? _resolve(
    String sourcePath,
    String specifier,
    Set<String> knownFiles,
  ) {
    if (!specifier.startsWith('.')) {
      return null;
    }
    final String base = path.posix.normalize(
      path.posix.join(path.posix.dirname(sourcePath), specifier),
    );
    final List<String> candidates = <String>[
      base,
      for (final String extension in _extensions) '$base$extension',
      for (final String extension in _extensions) '$base/index$extension',
    ];
    for (final String candidate in candidates) {
      if (knownFiles.contains(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  static const List<String> _extensions = <String>[
    '.js',
    '.jsx',
    '.mjs',
    '.cjs',
    '.ts',
    '.tsx',
    '.mts',
    '.cts',
  ];
}
