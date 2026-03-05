// Potentially catastrophic or misleading regular expressions need a purpose-built scanner that reasons about pattern structure.

import '../../core/models.dart';

/// Language-neutral regular-expression correctness and maintainability checks.
final class RegexRuleAnalysis {
  /// Finds suspicious regex literals and repeated compilation sites.
  List<Finding> findings(Map<String, String> sources) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      final Map<String, int> seenPatterns = <String, int>{};
      final bool supportsSlashLiterals = RegExp(
        r'\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$',
      ).hasMatch(entry.key.toLowerCase());
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final commentScan = _withoutComments(
          lines[index],
          inBlockComment: inBlockComment,
          hashComments: RegExp(r'\.(?:py|nim)$').hasMatch(entry.key),
          dashComments: RegExp(r'\.(?:lua|luau|sql)$').hasMatch(entry.key),
        );
        final String codeLine = commentScan.code;
        inBlockComment = commentScan.inBlockComment;
        for (final patternSite in _patterns(
          codeLine,
          supportsSlashLiterals: supportsSlashLiterals,
        )) {
          final String pattern = patternSite.pattern;
          // Runtime interpolation determines the final expression and cannot be
          // validated as a complete static regex literal.
          if (RegExp(r'(?<!\\)\$(?:[A-Za-z_]|\{)').hasMatch(pattern)) {
            continue;
          }
          void add(
            String id,
            RuleSeverity severity,
            String message, {
            String confidence = 'medium',
          }) {
            result.add(
              Finding(
                code: id,
                severity: severity,
                path: entry.key,
                line: index + 1,
                endLine: index + 1,
                message: message,
                confidence: confidence,
                why:
                    'This regular expression can be invalid, inefficient, misleading, or unsafe for validation.',
                suggestion:
                    'Simplify, anchor, precompile, or test the expression against adversarial input.',
              ),
            );
          }

          // RegExp syntax is runtime-specific. Dart's parser is authoritative
          // only for Dart source; Java, Python, Nim, and others have valid
          // constructs that Dart's ECMAScript-style engine rejects.
          if (entry.key.toLowerCase().endsWith('.dart') && patternSite.raw) {
            try {
              RegExp(pattern);
            } on FormatException {
              add(
                'regex-invalid',
                RuleSeverity.warn,
                'invalid regular expression',
                confidence: 'high',
              );
              continue;
            }
          }
          if (pattern.length == 1 &&
              RegExp(r'^[A-Za-z0-9]$').hasMatch(pattern)) {
            add(
              'regex-single-literal',
              RuleSeverity.info,
              'single-literal regular expression',
            );
          }
          if (patternSite.constructor && (seenPatterns[pattern] ?? 0) > 0) {
            add(
              'regex-repeated-compile',
              RuleSeverity.info,
              'regular expression compiled repeatedly',
            );
          }
          if (patternSite.constructor) {
            seenPatterns[pattern] = (seenPatterns[pattern] ?? 0) + 1;
          }
          if (_looksValidation(codeLine, patternSite) &&
              !pattern.startsWith('^') &&
              !pattern.startsWith(r'\A')) {
            add(
              'regex-unanchored-validation',
              RuleSeverity.warn,
              'validation regular expression is not anchored',
            );
          }
          if (_hasAmbiguousNestedRepetition(pattern)) {
            add(
              'regex-catastrophic-backtracking-risk',
              RuleSeverity.warn,
              'nested repetition may cause catastrophic backtracking',
            );
          }
          if (pattern.startsWith('.*') || pattern.startsWith('.+')) {
            add(
              'regex-leading-dot-star',
              RuleSeverity.info,
              'regular expression starts with broad wildcard',
            );
          }
          if (_hasEmptyAlternative(pattern)) {
            add(
              'regex-empty-alternative',
              RuleSeverity.info,
              'regular expression contains an empty alternative',
            );
          }
          if (pattern.contains('[A-z]')) {
            add(
              'regex-a-z-range',
              RuleSeverity.warn,
              '[A-z] includes punctuation between Z and a',
            );
          }
        }
      }
    }
    return result;
  }

  Iterable<({String pattern, bool constructor, bool raw, int start, int end})>
  _patterns(String line, {required bool supportsSlashLiterals}) sync* {
    for (final RegExpMatch match in RegExp(
      r'''(?:RegExp|re\.compile|Pattern\.compile)\s*\(\s*(r)?(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')(?:\s*,\s*["'][gimsuy]*["'])?\s*\)''',
    ).allMatches(line)) {
      yield (
        pattern: match.group(2) ?? match.group(3)!,
        constructor: true,
        raw: match.group(1) != null,
        start: match.start,
        end: match.end,
      );
    }
    if (supportsSlashLiterals) {
      final String code = _maskQuotedStringsAndComments(line);
      for (final RegExpMatch match in RegExp(
        r'(?<!/)/(?![/*])((?:\\.|[^/\n]){2,})/[gimsuy]*',
      ).allMatches(code)) {
        if (_canStartSlashLiteral(code, match.start)) {
          yield (
            pattern: match.group(1)!,
            constructor: false,
            raw: true,
            start: match.start,
            end: match.end,
          );
        }
      }
    }
  }

  bool _hasAmbiguousNestedRepetition(String pattern) {
    if (RegExp(r'(?:\.\*){2,}|(?:\.\+){2,}').hasMatch(pattern)) return true;
    for (final ({String inner, String quantifier}) group in _quantifiedGroups(
      pattern,
    )) {
      if (RegExp(r'^\{\d+\}$').hasMatch(group.quantifier) ||
          group.quantifier == '{0,1}') {
        continue;
      }
      final String inner = group.inner.replaceFirst(RegExp(r'^\?:'), '');
      // Repetition separated by a required literal delimiter consumes a
      // character the repeated atom cannot consume, so iterations cannot
      // overlap (for example `(?:[\w-]+\/)+`).
      if (RegExp(r'\\[^A-Za-z0-9]$').hasMatch(inner)) continue;
      if (inner.contains('.*') || inner.contains('.+')) return true;
      if (RegExp(r'^(?:\\.|\[[^]]+\]|[^\\])[+*]$').hasMatch(inner)) {
        return true;
      }
    }
    return false;
  }

  Iterable<({String inner, String quantifier})> _quantifiedGroups(
    String pattern,
  ) sync* {
    final List<int> starts = <int>[];
    var escaped = false;
    var inClass = false;
    for (var index = 0; index < pattern.length; index++) {
      final String character = pattern[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character == r'\') {
        escaped = true;
        continue;
      }
      if (character == '[') {
        inClass = true;
        continue;
      }
      if (character == ']' && inClass) {
        inClass = false;
        continue;
      }
      if (inClass) continue;
      if (character == '(') {
        starts.add(index);
        continue;
      }
      if (character != ')' || starts.isEmpty) continue;
      final int start = starts.removeLast();
      if (index + 1 >= pattern.length) continue;
      final String next = pattern[index + 1];
      if (next == '+' || next == '*') {
        yield (inner: pattern.substring(start + 1, index), quantifier: next);
      } else if (next == '{') {
        final int end = pattern.indexOf('}', index + 2);
        if (end > 0) {
          final String quantifier = pattern.substring(index + 1, end + 1);
          if (RegExp(r'^\{\d*,?\d*\}$').hasMatch(quantifier)) {
            yield (
              inner: pattern.substring(start + 1, index),
              quantifier: quantifier,
            );
          }
        }
      }
    }
  }

  bool _canStartSlashLiteral(String line, int offset) {
    final String prefix = line.substring(0, offset).trimRight();
    if (prefix.isEmpty) return true;
    final String previous = prefix[prefix.length - 1];
    if ('=([{,:;!?'.contains(previous)) return true;
    return RegExp(r'(?:return|case|throw|yield|=>)$').hasMatch(prefix);
  }

  ({String code, bool inBlockComment}) _withoutComments(
    String line, {
    required bool inBlockComment,
    required bool hashComments,
    required bool dashComments,
  }) {
    final StringBuffer code = StringBuffer();
    String? quote;
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      final String next = index + 1 < line.length ? line[index + 1] : '';
      if (inBlockComment) {
        if (character == '*' && next == '/') {
          inBlockComment = false;
          index++;
        }
        code.write(' ');
        continue;
      }
      if (quote != null) {
        code.write(character);
        if (escaped) {
          escaped = false;
        } else if (character == r'\') {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'" || character == '`') {
        quote = character;
        code.write(character);
        continue;
      }
      if (character == '/' && next == '*') {
        inBlockComment = true;
        code.write(' ');
        index++;
        continue;
      }
      if ((character == '/' && next == '/') ||
          (hashComments && character == '#') ||
          (dashComments && character == '-' && next == '-')) {
        break;
      }
      code.write(character);
    }
    return (code: code.toString(), inBlockComment: inBlockComment);
  }

  String _maskQuotedStringsAndComments(String line) {
    final StringBuffer result = StringBuffer();
    String? quote;
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      if (quote != null) {
        result.write(' ');
        if (escaped) {
          escaped = false;
        } else if (character == r'\') {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'" || character == '`') {
        quote = character;
        result.write(' ');
        continue;
      }
      if (character == '/' &&
          index + 1 < line.length &&
          line[index + 1] == '/') {
        result.write(' ' * (line.length - index));
        break;
      }
      result.write(character);
    }
    return result.toString();
  }

  bool _hasEmptyAlternative(String pattern) {
    var escaped = false;
    var inCharacterClass = false;
    var previousWasAlternative = false;
    for (var index = 0; index < pattern.length; index++) {
      final String character = pattern[index];
      if (escaped) {
        escaped = false;
        previousWasAlternative = false;
        continue;
      }
      if (character == r'\') {
        escaped = true;
        previousWasAlternative = false;
        continue;
      }
      if (character == '[') {
        inCharacterClass = true;
        previousWasAlternative = false;
        continue;
      }
      if (character == ']' && inCharacterClass) {
        inCharacterClass = false;
        continue;
      }
      if (character == '|' && !inCharacterClass) {
        if (index == 0 || previousWasAlternative) return true;
        previousWasAlternative = true;
        continue;
      }
      if (!inCharacterClass) previousWasAlternative = false;
    }
    return previousWasAlternative;
  }

  bool _looksValidation(
    String line,
    ({String pattern, bool constructor, bool raw, int start, int end})
    patternSite,
  ) {
    final String withoutPattern =
        '${line.substring(0, patternSite.start)}'
        '${' ' * (patternSite.end - patternSite.start)}'
        '${line.substring(patternSite.end)}';
    final String code = _maskQuotedStringsAndComments(withoutPattern);
    if (RegExp(r'\.toMatch\s*\(').hasMatch(code)) return false;
    if (!RegExp(
      r'\b(?:validation|validator|validate|isValid)\w*',
      caseSensitive: false,
    ).hasMatch(code)) {
      return false;
    }
    if (RegExp(
      r'\.(?:test|hasMatch|firstMatch|allMatches|matches|match)\s*\(',
    ).hasMatch(code)) {
      return true;
    }
    return RegExp(
      r'\b(?:validation|validator|validate|isValid)\w*\s*=',
      caseSensitive: false,
    ).hasMatch(code);
  }
}
