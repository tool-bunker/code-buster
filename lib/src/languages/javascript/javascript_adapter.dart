// JavaScript and TypeScript module forms vary widely, so this adapter normalizes their imports and function boundaries for shared analysis.

import 'package:path/path.dart' as path;
import '../../core/models.dart';

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Extracts named JavaScript and TypeScript function bodies for shared metrics.
final class JavaScriptFunctionAnalysis {
  final Map<String, int> _timings = <String, int>{};

  /// Wall-clock durations for lexical extraction components.
  Map<String, int> get timings => Map<String, int>.unmodifiable(_timings);

  /// Returns named declarations, methods, and block-bodied arrow functions.
  List<FunctionSource> functions(Map<String, String> sources) {
    _timings.clear();
    final List<FunctionSource> result = <FunctionSource>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String sourcePath in paths) {
      final String source = sources.requiredValue(sourcePath);
      final Stopwatch phase = Stopwatch()..start();
      final List<int> lineStarts = _lineStarts(source);
      _record('lineIndex', phase);
      phase
        ..reset()
        ..start();
      final String masked = _maskStringsAndComments(source);
      _record('masking', phase);
      phase
        ..reset()
        ..start();
      final Map<int, ({int start, String name})> candidates =
          <int, ({int start, String name})>{};
      for (final int keywordOffset in _functionKeywordOffsets(masked)) {
        final ({int brace, String name})? candidate = _functionCandidate(
          masked,
          keywordOffset,
        );
        if (candidate == null) continue;
        candidates.putIfAbsent(
          candidate.brace,
          () => (start: keywordOffset, name: candidate.name),
        );
      }
      _record('candidates.function', phase);
      phase
        ..reset()
        ..start();
      for (final entry in <({String name, RegExp pattern, String token})>[
        (name: 'method', pattern: _blockMethod, token: '('),
        (name: 'namedArrow', pattern: _arrowFunction, token: '='),
      ]) {
        for (final RegExpMatch match in _lineCandidates(
          masked,
          lineStarts,
          entry.pattern,
          entry.token,
        )) {
          final int brace = masked.indexOf('{', match.start);
          if (brace < 0 || brace >= match.end) continue;
          final String name = match.namedGroup('name') ?? '<anonymous>';
          if (_controlKeywords.contains(name)) continue;
          candidates.putIfAbsent(brace, () => (start: match.start, name: name));
        }
        _record('candidates.${entry.name}', phase);
        phase
          ..reset()
          ..start();
      }
      for (final RegExpMatch match in _blockArrowBody.allMatches(masked)) {
        final int brace = masked.indexOf('{', match.start);
        if (brace < 0 || brace >= match.end) continue;
        candidates.putIfAbsent(
          brace,
          () => (start: match.start, name: '<anonymous>'),
        );
      }
      _record('candidates.blockArrow', phase);
      phase
        ..reset()
        ..start();
      final List<int> braces = candidates.keys.toList()..sort();
      final Map<int, int> matchingBraces = _matchingBraces(masked);
      final Map<int, int> ends = <int, int>{
        for (final int brace in braces)
          if (matchingBraces[brace] case final int end) brace: end,
      };
      _record('braces', phase);
      phase
        ..reset()
        ..start();
      for (final int brace in braces) {
        final int? end = ends[brace];
        if (end == null) continue;
        final ({int start, String name}) candidate = candidates.requiredValue(
          brace,
        );
        result.add(
          FunctionSource(
            path: sourcePath,
            name: candidate.name,
            line: _lineNumberAt(lineStarts, candidate.start),
            source: _withoutNestedFunctions(
              source,
              start: candidate.start,
              opening: brace,
              end: end,
              candidates: candidates,
              ends: ends,
              sortedBraces: braces,
            ),
          ),
        );
      }
      _record('materialization', phase);
    }
    return result;
  }

  static const int _candidateWindow = 64 * 1024;
  static final RegExp _blockMethod = RegExp(
    r'^\s*(?:(?:public|private|protected|static|abstract|override|readonly|async|get|set)\s+)*(?<name>[A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?\s*\([^();{}]*\)\s*(?::\s*[^={};]+)?\s*\{',
    multiLine: true,
  );
  static final RegExp _arrowFunction = RegExp(
    r'^\s*(?:const|let|var)\s+(?<name>[A-Za-z_$][\w$]*)\s*(?:\??\s*:\s*[^=]+)?=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=>\s*\{',
    multiLine: true,
  );
  static final RegExp _blockArrowBody = RegExp(r'=>\s*\{');
  static const Set<String> _controlKeywords = <String>{
    'if',
    'for',
    'while',
    'switch',
    'catch',
    'with',
    'function',
  };

  static ({int brace, String name})? _functionCandidate(
    String source,
    int keywordOffset,
  ) {
    final int limit = keywordOffset + _candidateWindow < source.length
        ? keywordOffset + _candidateWindow
        : source.length;
    var offset = keywordOffset + 'function'.length;
    offset = _skipWhitespace(source, offset, limit);
    if (offset < limit && source.codeUnitAt(offset) == 42) {
      offset = _skipWhitespace(source, offset + 1, limit);
    }
    final int nameStart = offset;
    while (offset < limit && _isIdentifierCodeUnit(source.codeUnitAt(offset))) {
      offset++;
    }
    final String name = offset == nameStart
        ? '<anonymous>'
        : source.substring(nameStart, offset);
    offset = _skipWhitespace(source, offset, limit);
    if (offset >= limit || source.codeUnitAt(offset) != 40) return null;

    var depth = 1;
    for (offset++; offset < limit && depth > 0; offset++) {
      switch (source.codeUnitAt(offset)) {
        case 40:
          depth++;
        case 41:
          depth--;
      }
    }
    if (depth != 0) return null;
    for (; offset < limit; offset++) {
      switch (source.codeUnitAt(offset)) {
        case 123:
          return (brace: offset, name: name);
        case 59:
        case 61:
          return null;
      }
    }
    return null;
  }

  static int _skipWhitespace(String source, int offset, int limit) {
    while (offset < limit && source.codeUnitAt(offset) <= 32) {
      offset++;
    }
    return offset;
  }

  static Iterable<int> _functionKeywordOffsets(String source) sync* {
    const String keyword = 'function';
    var offset = 0;
    while (true) {
      offset = source.indexOf(keyword, offset);
      if (offset < 0) return;
      final int end = offset + keyword.length;
      final bool startsAtBoundary =
          offset == 0 || !_isIdentifierCodeUnit(source.codeUnitAt(offset - 1));
      final bool endsAtBoundary =
          end == source.length ||
          !_isIdentifierCodeUnit(source.codeUnitAt(end));
      if (startsAtBoundary && endsAtBoundary) yield offset;
      offset = end;
    }
  }

  static bool _isIdentifierCodeUnit(int codeUnit) =>
      (codeUnit >= 48 && codeUnit <= 57) ||
      (codeUnit >= 65 && codeUnit <= 90) ||
      codeUnit == 95 ||
      codeUnit == 36 ||
      (codeUnit >= 97 && codeUnit <= 122);

  static Iterable<RegExpMatch> _lineCandidates(
    String source,
    List<int> lineStarts,
    RegExp pattern,
    String token,
  ) sync* {
    for (var index = 0; index < lineStarts.length; index++) {
      final int start = lineStarts[index];
      final int end = index + 1 < lineStarts.length
          ? lineStarts[index + 1]
          : source.length;
      final int tokenOffset = source.indexOf(token, start);
      if (tokenOffset < 0 || tokenOffset >= end) continue;
      final Match? match = pattern.matchAsPrefix(source, start);
      if (match != null) yield match as RegExpMatch;
    }
  }

  void _record(String name, Stopwatch stopwatch) {
    _timings[name] = (_timings[name] ?? 0) + stopwatch.elapsedMilliseconds;
  }

  static Map<int, int> _matchingBraces(String source) {
    final List<int> openings = <int>[];
    final Map<int, int> result = <int, int>{};
    for (var index = 0; index < source.length; index++) {
      switch (source.codeUnitAt(index)) {
        case 123:
          openings.add(index);
        case 125 when openings.isNotEmpty:
          result[openings.removeLast()] = index;
      }
    }
    return result;
  }

  static String _withoutNestedFunctions(
    String source, {
    required int start,
    required int opening,
    required int end,
    required Map<int, ({int start, String name})> candidates,
    required Map<int, int> ends,
    required List<int> sortedBraces,
  }) {
    final List<int> result = source
        .substring(start, end + 1)
        .codeUnits
        .toList();
    var nestedIndex = _firstGreaterThan(sortedBraces, opening);
    while (nestedIndex < sortedBraces.length) {
      final int nestedOpening = sortedBraces[nestedIndex++];
      if (nestedOpening > end) break;
      final int? nestedEnd = ends[nestedOpening];
      if (nestedEnd == null || nestedEnd > end) continue;
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

  static List<int> _lineStarts(String source) {
    final List<int> result = <int>[0];
    for (var index = 0; index < source.length; index++) {
      if (source.codeUnitAt(index) == 10) result.add(index + 1);
    }
    return result;
  }

  static int _lineNumberAt(List<int> lineStarts, int offset) {
    var low = 0;
    var high = lineStarts.length;
    while (low < high) {
      final int middle = low + ((high - low) >> 1);
      if (lineStarts[middle] <= offset) {
        low = middle + 1;
      } else {
        high = middle;
      }
    }
    return low;
  }

  static int _firstGreaterThan(List<int> values, int target) {
    var low = 0;
    var high = values.length;
    while (low < high) {
      final int middle = low + ((high - low) >> 1);
      if (values[middle] <= target) {
        low = middle + 1;
      } else {
        high = middle;
      }
    }
    return low;
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
