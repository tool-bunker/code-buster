// Duplicate blocks and near-duplicate functions need normalization and cross-file comparison that no single language rule should reimplement.

import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../../core/models.dart';
import '../../engine/analysis.dart';
import '../../languages/rust/rust_adapter.dart';

const Set<String> _structuralKeywords = <String>{
  'if',
  'else',
  'elif',
  'elseif',
  'then',
  'for',
  'while',
  'case',
  'switch',
  'of',
  'return',
  'yield',
  'break',
  'continue',
  'try',
  'except',
  'catch',
  'finally',
  'raise',
  'throw',
  'and',
  'or',
  'not',
  'in',
  'is',
  'as',
  'new',
  'await',
  'async',
  'true',
  'false',
  'nil',
  'null',
};

/// Exact, structural, and repeated-condition duplicate analysis.
final class DuplicationAnalysis {
  /// Creates duplicate analysis with a bounded number of reported groups.
  const DuplicationAnalysis({
    this.maxGroups = 50,
    this.maxNearDuplicatePairs = 30,
    this.maxOccurrencesPerGroup = 32,
  });

  /// Maximum exact duplicate groups emitted per analysis.
  final int maxGroups;

  /// Maximum near-duplicate function pairs emitted per analysis.
  final int maxNearDuplicatePairs;

  /// Maximum deterministic locations retained for one duplicate fingerprint.
  final int maxOccurrencesPerGroup;

  /// Returns normalized source text suitable for exact-block comparison.
  static String normalizedLine(String line) {
    final String normalized = line.trim().replaceAll(RegExp(r'\s+'), ' ');
    if (normalized.isEmpty ||
        normalized.startsWith('--') ||
        normalized.startsWith('//') ||
        normalized.startsWith('using ') ||
        normalized.startsWith('namespace ') ||
        normalized.startsWith('#nullable') ||
        normalized.startsWith('#pragma') ||
        normalized == '{' ||
        normalized == '}' ||
        normalized == '{}') {
      return '';
    }
    return normalized;
  }

  /// Finds exact normalized blocks across [sources].
  List<Finding> exactBlocks(
    Map<String, String> sources, {
    required int minLines,
  }) {
    final int window = minLines < 3 ? 3 : minLines;
    final Map<String, List<_Location>> occurrences =
        <String, List<_Location>>{};
    final Map<String, List<_NormalizedLine>> normalizedByPath =
        <String, List<_NormalizedLine>>{};
    final List<String> paths = sources.keys.toList()..sort();
    for (final String path in paths) {
      if (_migrationSql(path)) continue;
      final List<_NormalizedLine> lines = _normalizedLines(
        sources[path]!,
        path,
      );
      normalizedByPath[path] = lines;
      if (lines.length < window) {
        continue;
      }
      for (var start = 0; start <= lines.length - window; start++) {
        final String extension = path.substring(path.lastIndexOf('.'));
        final String languageKey = extension == '.luau' ? '.lua' : extension;
        final String key =
            '$languageKey\n${lines.sublist(start, start + window).map((_NormalizedLine line) => line.text).join('\n')}';
        final List<_Location> locations = occurrences.putIfAbsent(
          key,
          () => <_Location>[],
        );
        if (locations.length < maxOccurrencesPerGroup) {
          locations.add(_Location(path, lines[start].number, start));
        }
      }
    }

    final List<MapEntry<String, List<_Location>>> candidates =
        occurrences.entries
            .where(
              (MapEntry<String, List<_Location>> entry) =>
                  entry.value.length > 1,
            )
            .toList()
          ..sort((
            MapEntry<String, List<_Location>> a,
            MapEntry<String, List<_Location>> b,
          ) {
            final _Location firstA = a.value.reduce(_earlier);
            final _Location firstB = b.value.reduce(_earlier);
            final int pathOrder = firstA.path.compareTo(firstB.path);
            return pathOrder == 0
                ? firstA.line.compareTo(firstB.line)
                : pathOrder;
          });

    final Map<String, List<_LineRange>> occupied = <String, List<_LineRange>>{};
    final List<Finding> result = <Finding>[];
    var groups = 0;
    for (final MapEntry<String, List<_Location>> candidate in candidates) {
      if (groups >= maxGroups) {
        break;
      }
      final List<_Location> orderedLocations = candidate.value.toSet().toList()
        ..sort((_Location a, _Location b) {
          final int pathOrder = a.path.compareTo(b.path);
          return pathOrder == 0 ? a.line.compareTo(b.line) : pathOrder;
        });
      final List<_Location> locations = <_Location>[];
      for (final _Location location in orderedLocations) {
        if (locations.any(
          (_Location selected) =>
              selected.path == location.path &&
              (selected.index - location.index).abs() < window,
        )) {
          continue;
        }
        locations.add(location);
      }
      if (locations.length < 2) continue;
      if (locations.any((_Location location) {
        final List<_NormalizedLine> lines = normalizedByPath[location.path]!;
        return _overlaps(
          occupied[location.path] ?? const <_LineRange>[],
          _LineRange(
            lines[location.index].number,
            lines[location.index + window - 1].number,
          ),
        );
      })) {
        continue;
      }
      var backward = 0;
      while (locations.every(
        (_Location location) => location.index > backward,
      )) {
        final Set<String> previous = locations
            .map(
              (_Location location) =>
                  normalizedByPath[location.path]![location.index -
                          backward -
                          1]
                      .text,
            )
            .toSet();
        if (previous.length != 1) break;
        backward++;
      }
      var forward = 0;
      while (locations.every(
        (_Location location) =>
            location.index + window + forward <
            normalizedByPath[location.path]!.length,
      )) {
        final Set<String> next = locations
            .map(
              (_Location location) =>
                  normalizedByPath[location.path]![location.index +
                          window +
                          forward]
                      .text,
            )
            .toSet();
        if (next.length != 1) break;
        forward++;
      }
      final List<_DuplicateSpan> spans = locations
          .map((_Location location) {
            final List<_NormalizedLine> lines =
                normalizedByPath[location.path]!;
            final int startIndex = location.index - backward;
            final int endIndex = location.index + window + forward - 1;
            return _DuplicateSpan(
              location.path,
              lines[startIndex].number,
              lines[endIndex].number,
              startIndex,
              endIndex,
            );
          })
          .toList(growable: false);
      var spansOverlap = false;
      for (var index = 0; index < spans.length && !spansOverlap; index++) {
        for (var other = index + 1; other < spans.length; other++) {
          final _DuplicateSpan left = spans[index];
          final _DuplicateSpan right = spans[other];
          if (left.path == right.path &&
              left.startIndex <= right.endIndex &&
              right.startIndex <= left.endIndex) {
            spansOverlap = true;
            break;
          }
        }
      }
      if (spansOverlap) continue;
      if (spans.any(
        (_DuplicateSpan span) => _overlaps(
          occupied[span.path] ?? const <_LineRange>[],
          _LineRange(span.startLine, span.endLine),
        ),
      )) {
        continue;
      }
      final _DuplicateSpan firstSpan = spans.first;
      final List<String> maximalLines = normalizedByPath[firstSpan.path]!
          .sublist(firstSpan.startIndex, firstSpan.endIndex + 1)
          .map((_NormalizedLine line) => line.text)
          .toList(growable: false);
      if (_mostlyLiteralData(maximalLines) || _mostlyCaseLabels(maximalLines)) {
        continue;
      }
      groups++;
      final String fingerprint = sha256
          .convert(
            utf8.encode(
              '${candidate.key.split('\n').first}\n${maximalLines.join('\n')}',
            ),
          )
          .toString()
          .toUpperCase()
          .substring(0, 12);
      final String snippet = maximalLines
          .take(3)
          .map((String line) => '    ${line.trim()}')
          .join('\n');
      for (final _DuplicateSpan span in spans) {
        occupied
            .putIfAbsent(span.path, () => <_LineRange>[])
            .add(_LineRange(span.startLine, span.endLine));
      }
      result.add(
        Finding(
          code: 'duplicate-block',
          severity: RuleSeverity.warn,
          path: firstSpan.path,
          line: firstSpan.startLine,
          endLine: firstSpan.endLine,
          message:
              'duplicate block of ${maximalLines.length} lines fingerprint=$fingerprint',
          confidence: 'high',
          why:
              'The same normalized code block appears in more than one location.',
          suggestion:
              'Extract shared logic or raise min_duplication_lines if the duplication is intentional/noisy.',
          relatedFiles: spans
              .skip(1)
              .map(
                (_DuplicateSpan other) =>
                    '${other.path}:${other.startLine}-${other.endLine}',
              )
              .toList(growable: false),
          snippet: snippet,
        ),
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  /// Normalizes identifiers and literals while retaining operations and control flow.
  static List<String> structuralTokens(String source) {
    final String noStrings = source.replaceAll(
      RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' '''.trim()),
      ' STR ',
    );
    final List<String> raw = RegExp(
      r'[A-Za-z_]\w*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||[-+*/%<>{}()[\].,:=]',
    ).allMatches(noStrings).map((RegExpMatch match) => match.group(0)!).toList();
    return List<String>.unmodifiable(
      List<String>.generate(raw.length, (int index) {
        final String token = raw[index];
        if (RegExp(r'^\d').hasMatch(token)) {
          return 'NUM';
        }
        if (RegExp(r'^[A-Za-z_]').hasMatch(token)) {
          final String lower = token.toLowerCase();
          final bool call = index + 1 < raw.length && raw[index + 1] == '(';
          final bool member = index > 0 && raw[index - 1] == '.';
          return _structuralKeywords.contains(lower) || call || member
              ? lower
              : 'ID';
        }
        return token;
      }),
    );
  }

  /// Returns Levenshtein similarity in the inclusive range `0.0..1.0`.
  static double sequenceSimilarity(List<String> left, List<String> right) {
    if (left.isEmpty && right.isEmpty) {
      return 1;
    }
    if (left.isEmpty || right.isEmpty) {
      return 0;
    }
    List<int> previous = List<int>.generate(
      right.length + 1,
      (int index) => index,
    );
    List<int> current = List<int>.filled(right.length + 1, 0);
    for (var leftIndex = 1; leftIndex <= left.length; leftIndex++) {
      current[0] = leftIndex;
      for (var rightIndex = 1; rightIndex <= right.length; rightIndex++) {
        current[rightIndex] = _min3(
          previous[rightIndex] + 1,
          current[rightIndex - 1] + 1,
          previous[rightIndex - 1] +
              (left[leftIndex - 1] == right[rightIndex - 1] ? 0 : 1),
        );
      }
      final List<int> next = previous;
      previous = current;
      current = next;
    }
    return 1 -
        previous[right.length] /
            (left.length > right.length ? left.length : right.length);
  }

  /// Finds structurally similar, non-identical function fragments.
  List<Finding> nearDuplicateFunctions(Iterable<FunctionSource> fragments) {
    final List<_TokenizedFragment> candidates = fragments
        .map((_toTokenized))
        .where(
          (_TokenizedFragment fragment) =>
              fragment.tokens.length >= 20 &&
              fragment.tokens.length <= 400 &&
              fragment.fragment.source.split('\n').length >= 7 &&
              !RegExp(
                r'^accept[A-Z].*Visitor$',
              ).hasMatch(fragment.fragment.name),
        )
        .toList(growable: false);
    final Map<int, ({int other, double similarity})> best =
        <int, ({int other, double similarity})>{};
    final Map<String, List<int>> buckets = <String, List<int>>{};
    for (var index = 0; index < candidates.length; index++) {
      buckets
          .putIfAbsent(_shapeKey(candidates[index]), () => <int>[])
          .add(index);
    }
    for (final List<int> bucket in buckets.values) {
      for (var leftPosition = 0; leftPosition < bucket.length; leftPosition++) {
        final int leftIndex = bucket[leftPosition];
        for (
          var rightPosition = leftPosition + 1;
          rightPosition < bucket.length;
          rightPosition++
        ) {
          final int rightIndex = bucket[rightPosition];
          final _TokenizedFragment left = candidates[leftIndex];
          final _TokenizedFragment right = candidates[rightIndex];
          final int shortest = left.tokens.length < right.tokens.length
              ? left.tokens.length
              : right.tokens.length;
          final int longest = left.tokens.length > right.tokens.length
              ? left.tokens.length
              : right.tokens.length;
          if (shortest / longest < 0.8) continue;
          final double similarity = sequenceSimilarity(
            left.tokens,
            right.tokens,
          );
          if (similarity < 0.86 || similarity >= 0.999) continue;
          final currentLeft = best[leftIndex];
          if (currentLeft == null || similarity > currentLeft.similarity) {
            best[leftIndex] = (other: rightIndex, similarity: similarity);
          }
          final currentRight = best[rightIndex];
          if (currentRight == null || similarity > currentRight.similarity) {
            best[rightIndex] = (other: leftIndex, similarity: similarity);
          }
        }
      }
    }
    final List<Finding> result = <Finding>[];
    for (final int index in best.keys.toList()..sort()) {
      if (result.length >= maxNearDuplicatePairs * 2) break;
      final match = best[index]!;
      result.add(
        _nearDuplicateFinding(
          candidates[index],
          candidates[match.other],
          (match.similarity * 100).floor(),
          match.similarity,
        ),
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  static String _shapeKey(_TokenizedFragment fragment) {
    final String path = fragment.fragment.path;
    final String extension = path.contains('.') ? path.split('.').last : '';
    final List<String> shape = fragment.tokens
        .where(
          (String token) =>
              token != 'ID' &&
              token != 'NUM' &&
              token != 'STR' &&
              (!RegExp(r'^[A-Za-z_]').hasMatch(token) ||
                  _structuralKeywords.contains(token)),
        )
        .take(12)
        .toList(growable: false);
    return '$extension|${shape.join(',')}';
  }

  /// Finds separate functions that implement the same external contract.
  List<Finding> parallelContractImplementations(
    Iterable<FunctionSource> fragments,
  ) {
    final Map<String, List<_ContractOccurrence>> groups =
        <String, List<_ContractOccurrence>>{};
    final List<FunctionSource> ordered = fragments.toList(growable: false)
      ..sort((FunctionSource left, FunctionSource right) {
        final int path = left.path.compareTo(right.path);
        return path != 0 ? path : left.line.compareTo(right.line);
      });
    for (final FunctionSource fragment in ordered) {
      for (final _ContractSignature signature in _contractSignatures(
        fragment,
      )) {
        groups
            .putIfAbsent(signature.id, () => <_ContractOccurrence>[])
            .add(_ContractOccurrence(fragment, signature));
      }
    }

    final List<Finding> result = <Finding>[];
    for (final String id in groups.keys.toList()..sort()) {
      if (result.length >= maxNearDuplicatePairs) break;
      final List<_ContractOccurrence> occurrences = groups[id]!;
      if (occurrences.map((item) => item.fragment.path).toSet().length < 2) {
        continue;
      }
      final _ContractOccurrence primary = occurrences.first;
      final _ContractOccurrence comparison = occurrences.firstWhere(
        (_ContractOccurrence item) =>
            item.fragment.path != primary.fragment.path,
      );
      final double similarity = sequenceSimilarity(
        structuralTokens(primary.fragment.source),
        structuralTokens(comparison.fragment.source),
      );
      if (similarity >= 0.999) continue;
      final int percent = (similarity * 100).round();
      result.add(
        Finding(
          code: 'parallel-contract-implementation',
          severity: RuleSeverity.info,
          path: primary.fragment.path,
          line: primary.line,
          endLine: primary.fragment.endLine,
          message:
              '${occurrences.length} functions independently implement '
              '${primary.signature.label}; normalized bodies are $percent% similar',
          confidence: primary.signature.confidence,
          why:
              'Separate implementations of one external contract can drift when generated or maintained independently.',
          suggestion:
              'Review whether one implementation should own this contract, then delegate or share its typed decoder and policy.',
          relatedFiles: occurrences
              .skip(1)
              .map(
                (_ContractOccurrence item) =>
                    '${item.fragment.path}:${item.line}-${item.fragment.endLine}',
              )
              .toList(growable: false),
          snippet:
              '${primary.fragment.name}: ${primary.signature.label}; structural similarity $percent%',
        ),
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  static List<_ContractSignature> _contractSignatures(FunctionSource fragment) {
    final String source = fragment.source;
    final Map<String, _ContractSignature> signatures =
        <String, _ContractSignature>{};
    for (final RegExpMatch match in RegExp(
      r'''\b(get|post|put|patch|delete)\s*\(\s*(?:Uri\.parse\(\s*)?['"]([^'"]+)['"]''',
      caseSensitive: false,
    ).allMatches(source)) {
      final String method = match.group(1)!.toUpperCase();
      final String endpoint = _normalizeEndpoint(match.group(2)!);
      if (!endpoint.startsWith('/')) continue;
      final String id = 'http:$method:$endpoint';
      signatures[id] = _ContractSignature(
        id,
        'HTTP $method $endpoint',
        'high',
        match.start,
      );
    }

    final List<RegExpMatch> jsonKeys = RegExp(
      r'''(?:json|map|data|body|payload)\s*\[\s*['"]([^'"]+)['"]\s*\]''',
      caseSensitive: false,
    ).allMatches(source).toList(growable: false);
    final Set<String> keys = jsonKeys
        .map((RegExpMatch match) => match.group(1)!)
        .toSet();
    if (keys.length >= 3) {
      final List<String> orderedKeys = keys.toList()..sort();
      final String schema = orderedKeys.join(',');
      signatures['json:$schema'] = _ContractSignature(
        'json:$schema',
        'JSON keys ${orderedKeys.join(', ')}',
        'medium',
        jsonKeys.first.start,
      );
    }

    for (final RegExpMatch match in RegExp(
      r'\b(select\s+[^;\n]{1,200}?\s+from|insert\s+into|update|delete\s+from)\s+([a-z_][\w.]*)',
      caseSensitive: false,
    ).allMatches(source)) {
      final String operation = match
          .group(1)!
          .toLowerCase()
          .split(RegExp(r'\s+'))
          .first;
      if (operation == 'update' &&
          !RegExp(
            r'^\s+set\b',
            caseSensitive: false,
          ).hasMatch(source.substring(match.end))) {
        continue;
      }
      final String table = match.group(2)!.toLowerCase();
      final String id = 'sql:$operation:$table';
      signatures[id] = _ContractSignature(
        id,
        'SQL $operation on $table',
        'high',
        match.start,
      );
    }

    final List<RegExpMatch> configKeys = RegExp(
      r'''(?:Platform\.environment|process\.env)\s*(?:\[\s*['"]([^'"]+)['"]\s*\]|\.\s*([A-Za-z_]\w*))|getenv\s*\(\s*['"]([^'"]+)['"]''',
    ).allMatches(source).toList(growable: false);
    final Set<String> environmentKeys = configKeys
        .map(
          (RegExpMatch match) =>
              match.group(1) ?? match.group(2) ?? match.group(3)!,
        )
        .toSet();
    if (environmentKeys.length >= 2) {
      final List<String> orderedKeys = environmentKeys.toList()..sort();
      final String contract = orderedKeys.join(',');
      signatures['config:$contract'] = _ContractSignature(
        'config:$contract',
        'configuration keys ${orderedKeys.join(', ')}',
        'medium',
        configKeys.first.start,
      );
    }
    return signatures.values.toList(growable: false);
  }

  static String _normalizeEndpoint(String endpoint) => endpoint
      .split('?')
      .first
      .replaceAll(RegExp(r'\$\{?[A-Za-z_]\w*\}?'), '{value}')
      .replaceAll(RegExp(r'(?<=/)\d+(?=/|$)'), '{number}');

  /// Finds complex conditions repeated in at least three locations.
  List<Finding> repeatedConditions(Map<String, String> sources) {
    final Map<String, List<_Condition>> occurrences =
        <String, List<_Condition>>{};
    sources.forEach((String path, String source) {
      final List<String> lines = source.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index].trim();
        if (!RegExp(r'^(?:if|elif|elseif|else if|while)\s+').hasMatch(raw)) {
          continue;
        }
        final String condition = _conditionSource(raw);
        if (!(condition.contains(' and ') ||
            condition.contains(' or ') ||
            condition.contains('&&') ||
            condition.contains('||'))) {
          continue;
        }
        final List<String> tokens = structuralTokens(condition);
        if (tokens.length < 8) {
          continue;
        }
        final String normalizedCondition = condition
            .replaceAll(RegExp(r'\s+'), ' ')
            .trim();
        occurrences
            .putIfAbsent('$path | $normalizedCondition', () => <_Condition>[])
            .add(_Condition(path, index + 1, condition));
      }
    });
    final List<Finding> result = <Finding>[];
    var groups = 0;
    final List<String> keys = occurrences.keys.toList()..sort();
    for (final String key in keys) {
      final List<_Condition> locations = occurrences[key]!;
      if (locations.length < 3 || groups >= 20) {
        continue;
      }
      groups++;
      final _Condition location = locations.first;
      result.add(
        Finding(
          code: 'repeated-condition',
          severity: RuleSeverity.info,
          path: location.path,
          line: location.line,
          endLine: location.line,
          message:
              'complex condition is repeated in ${locations.length} locations',
          confidence: 'medium',
          why:
              'Repeated policy conditions can drift when one copy changes without the others.',
          suggestion:
              'Consider a named predicate if these checks express the same business rule and should evolve together.',
          relatedFiles: locations
              .skip(1)
              .map((_Condition other) => '${other.path}:${other.line}')
              .toList(growable: false),
          snippet: location.source,
        ),
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  static bool _mostlyLiteralData(List<String> lines) {
    if (lines.length < 10) return false;
    final RegExp literal = RegExp(
      r'''^(?:(?:r)?["'].*["'],?|(?:(?:null|nullptr|nil|none|true|false)\s*,?|(?:[\{\[]\s*)?(?:[-+]?(?:0x[0-9a-f]+|0b[01]+|\d+(?:\.\d*)?(?:e[-+]?\d+)?)[ulf]*)(?:\s*,\s*[-+]?(?:0x[0-9a-f]+|0b[01]+|\d+(?:\.\d*)?(?:e[-+]?\d+)?)[ulf]*)*(?:\s*[\}\]])?,?))\s*(?://.*|/\*.*\*/)?$''',
      caseSensitive: false,
    );
    final int literalLines = lines.where(literal.hasMatch).length;
    return literalLines * 5 >= lines.length * 4;
  }

  static bool _mostlyCaseLabels(List<String> lines) {
    if (lines.length < 10) return false;
    final RegExp label = RegExp(r'^(?:case\s+.+|default):$');
    final int labelLines = lines.where(label.hasMatch).length;
    return labelLines * 5 >= lines.length * 4;
  }

  static bool _migrationSql(String sourcePath) {
    final String normalized = sourcePath.replaceAll('\\', '/').toLowerCase();
    return normalized.endsWith('.sql') &&
        RegExp(r'(^|/)migrations?(/|$)').hasMatch(normalized);
  }

  static List<_NormalizedLine> _normalizedLines(
    String source,
    String sourcePath,
  ) {
    final List<_NormalizedLine> result = <_NormalizedLine>[];
    final List<String> lines = source.split('\n');
    final Set<int> rustTestLines = sourcePath.endsWith('.rs')
        ? rustCfgTestLines(lines)
        : const <int>{};
    final bool hasHashLineComments = RegExp(
      r'\.pyw?$',
      caseSensitive: false,
    ).hasMatch(sourcePath);
    final bool hasLuaLongComments = RegExp(
      r'\.lua(?:u)?$',
      caseSensitive: false,
    ).hasMatch(sourcePath);
    final _LuaLongCommentState? luaLongCommentState = hasLuaLongComments
        ? _LuaLongCommentState()
        : null;
    var inBlockComment = false;
    for (var index = 0; index < lines.length; index++) {
      if (rustTestLines.contains(index)) continue;
      if (hasHashLineComments && lines[index].trimLeft().startsWith('#')) {
        continue;
      }
      var line = lines[index];
      if (luaLongCommentState != null) {
        line = _withoutLuaLongComments(line, luaLongCommentState);
        if (luaLongCommentState.end != null && line.isEmpty) continue;
      }
      if (inBlockComment) {
        final int end = line.indexOf('*/');
        if (end < 0) continue;
        line = line.substring(end + 2);
        inBlockComment = false;
      }
      final int commentStart = line.indexOf('/*');
      if (commentStart >= 0) {
        final int commentEnd = line.indexOf('*/', commentStart + 2);
        if (commentEnd < 0) {
          line = line.substring(0, commentStart);
          inBlockComment = true;
        } else {
          line =
              '${line.substring(0, commentStart)} '
              '${line.substring(commentEnd + 2)}';
        }
      }
      final String normalized = normalizedLine(line);
      if (normalized.isNotEmpty) {
        result.add(_NormalizedLine(index + 1, normalized));
      }
    }
    return result;
  }

  static final RegExp _luaLongCommentStart = RegExp(r'--\[(=*)\[');

  static String _withoutLuaLongComments(
    String line,
    _LuaLongCommentState state,
  ) {
    var result = line;
    var searchFrom = 0;
    if (state.end != null) {
      final int end = result.indexOf(state.end!);
      if (end < 0) return '';
      result = result.substring(end + state.end!.length);
      state.end = null;
    }
    while (true) {
      RegExpMatch? start;
      for (final RegExpMatch candidate in _luaLongCommentStart.allMatches(
        result,
        searchFrom,
      )) {
        if (!_insideLuaString(result, candidate.start)) {
          start = candidate;
          break;
        }
      }
      if (start == null) return result;
      final int startIndex = start.start;
      final String endMarker = ']${start.group(1)!}]';
      final int endIndex = result.indexOf(
        endMarker,
        startIndex + start.group(0)!.length,
      );
      if (endIndex < 0) {
        state.end = endMarker;
        return result.substring(0, startIndex);
      }
      result =
          '${result.substring(0, startIndex)}'
          '${result.substring(endIndex + endMarker.length)}';
      searchFrom = startIndex;
    }
  }

  static bool _insideLuaString(String line, int end) {
    var index = 0;
    while (index < end) {
      final int character = line.codeUnitAt(index);
      if (character == 0x22 || character == 0x27 || character == 0x60) {
        final int quote = character;
        index++;
        while (index < end) {
          if (line.codeUnitAt(index) == 0x5c) {
            index += 2;
          } else if (line.codeUnitAt(index) == quote) {
            index++;
            break;
          } else {
            index++;
          }
        }
        if (index >= end && line.codeUnitAt(end - 1) != quote) return true;
        continue;
      }
      if (character == 0x5b) {
        var delimiterEnd = index + 1;
        while (delimiterEnd < end && line.codeUnitAt(delimiterEnd) == 0x3d) {
          delimiterEnd++;
        }
        if (delimiterEnd < end && line.codeUnitAt(delimiterEnd) == 0x5b) {
          final String close = ']${line.substring(index + 1, delimiterEnd)}]';
          final int closeIndex = line.indexOf(close, delimiterEnd + 1);
          if (closeIndex < 0 || closeIndex >= end) return true;
          index = closeIndex + close.length;
          continue;
        }
      }
      index++;
    }
    return false;
  }

  static _TokenizedFragment _toTokenized(FunctionSource fragment) =>
      _TokenizedFragment(fragment, structuralTokens(fragment.source));

  static Finding _nearDuplicateFinding(
    _TokenizedFragment item,
    _TokenizedFragment other,
    int percent,
    double similarity,
  ) => Finding(
    code: 'near-duplicate-function',
    severity: RuleSeverity.info,
    path: item.fragment.path,
    line: item.fragment.line,
    endLine: item.fragment.endLine,
    message:
        '${item.fragment.name} is $percent% structurally similar to ${other.fragment.name}',
    confidence: similarity >= 0.93 ? 'high' : 'medium',
    why:
        'The functions have nearly the same operations and control flow despite identifier or literal differences.',
    suggestion:
        'Consider a shared function when these implementations should evolve together.',
    relatedFiles: <String>[
      '${other.fragment.path}:${other.fragment.line}-${other.fragment.endLine}',
    ],
    snippet: item.fragment.source.split('\n').take(3).join('\n'),
  );

  static String _conditionSource(String value) {
    String result = value;
    for (final String prefix in <String>[
      'else if ',
      'elseif ',
      'elif ',
      'if ',
      'while ',
    ]) {
      if (result.startsWith(prefix)) {
        result = result.substring(prefix.length);
        break;
      }
    }
    if (result.startsWith('(') && result.endsWith(') {')) {
      result = result.substring(1, result.length - 2);
    } else if (result.endsWith(' then')) {
      result = result.substring(0, result.length - 5);
    } else if (result.endsWith(' {') || result.endsWith(':')) {
      result = result.substring(
        0,
        result.length - (result.endsWith(':') ? 1 : 2),
      );
    }
    return result.trim();
  }
}

final class _LuaLongCommentState {
  String? end;
}

final class _Location {
  const _Location(this.path, this.line, this.index);

  final String path;
  final int line;
  final int index;

  @override
  bool operator ==(Object other) =>
      other is _Location && path == other.path && line == other.line;

  @override
  int get hashCode => Object.hash(path, line);
}

final class _DuplicateSpan {
  const _DuplicateSpan(
    this.path,
    this.startLine,
    this.endLine,
    this.startIndex,
    this.endIndex,
  );

  final String path;
  final int startLine;
  final int endLine;
  final int startIndex;
  final int endIndex;
}

final class _NormalizedLine {
  const _NormalizedLine(this.number, this.text);

  final int number;
  final String text;
}

final class _LineRange {
  const _LineRange(this.start, this.end);

  final int start;
  final int end;
}

final class _TokenizedFragment {
  const _TokenizedFragment(this.fragment, this.tokens);

  final FunctionSource fragment;
  final List<String> tokens;
}

final class _ContractSignature {
  const _ContractSignature(this.id, this.label, this.confidence, this.offset);

  final String id;
  final String label;
  final String confidence;
  final int offset;
}

final class _ContractOccurrence {
  const _ContractOccurrence(this.fragment, this.signature);

  final FunctionSource fragment;
  final _ContractSignature signature;

  int get line =>
      fragment.line +
      '\n'.allMatches(fragment.source.substring(0, signature.offset)).length;
}

final class _Condition {
  const _Condition(this.path, this.line, this.source);

  final String path;
  final int line;
  final String source;

  @override
  bool operator ==(Object other) =>
      other is _Condition && path == other.path && line == other.line;

  @override
  int get hashCode => Object.hash(path, line);
}

_Location _earlier(_Location left, _Location right) {
  final int pathOrder = left.path.compareTo(right.path);
  return pathOrder < 0 || (pathOrder == 0 && left.line <= right.line)
      ? left
      : right;
}

bool _overlaps(Iterable<_LineRange> ranges, _LineRange candidate) => ranges.any(
  (_LineRange range) =>
      candidate.start <= range.end && candidate.end >= range.start,
);

int _min3(int first, int second, int third) =>
    first < second && first < third ? first : (second < third ? second : third);
