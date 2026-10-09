// Rust rules and adapters share this lexical model so comments, literals, attributes, and block ranges are interpreted once.

import '../../core/regexp_cache.dart';

/// Parse-once lexical facts for all Rust sources in one analysis run.
final class RustAnalysis {
  RustAnalysis(Map<String, String> sources)
    : files = Map<String, RustFileAnalysis>.unmodifiable(
        sources.map(
          (String path, String source) => MapEntry<String, RustFileAnalysis>(
            path,
            RustFileAnalysis(source),
          ),
        ),
      );

  final Map<String, RustFileAnalysis> files;
}

/// Position-preserving lexical facts for one Rust source file.
final class RustFileAnalysis {
  RustFileAnalysis(this.source) {
    final _RustScan scan = _scanRust(source);
    masked = scan.masked;
    commentsMasked = scan.commentsMasked;
    commentRanges = List<RustCommentRange>.unmodifiable(scan.comments);
    lines = List<String>.unmodifiable(masked.split('\n'));
    commentsMaskedLines = List<String>.unmodifiable(commentsMasked.split('\n'));
    testLines = Set<int>.unmodifiable(_attributedLines(lines, _testOnly));
  }

  final String source;
  late final String masked;
  late final String commentsMasked;
  late final List<String> lines;
  late final List<String> commentsMaskedLines;
  late final List<RustCommentRange> commentRanges;
  late final Set<int> testLines;

  int lineAt(int offset) =>
      1 +
      '\n'
          .allMatches(source.substring(0, offset.clamp(0, source.length)))
          .length;

  /// Returns the matching closing brace in masked source, or -1.
  int matchingBrace(int open) {
    if (open < 0 || open >= masked.length || masked[open] != '{') return -1;
    var depth = 0;
    for (var index = open; index < masked.length; index++) {
      if (masked[index] == '{') {
        depth++;
      } else if (masked[index] == '}' && --depth == 0) {
        return index;
      }
    }
    return -1;
  }

  /// Whether an unsafe boundary has a nearby nonempty SAFETY rationale.
  bool hasSafetyRationale(int unsafeOffset, int openBrace) {
    final int lineStart = source.lastIndexOf('\n', unsafeOffset - 1) + 1;
    final List<RustCommentRange> preceding = commentRanges
        .where((RustCommentRange range) => range.end <= lineStart)
        .toList(growable: false);
    if (preceding.isNotEmpty) {
      var first = preceding.length - 1;
      if (source.substring(preceding[first].end, lineStart).trim().isEmpty) {
        while (first > 0 &&
            source
                .substring(preceding[first - 1].end, preceding[first].start)
                .trim()
                .isEmpty) {
          first--;
        }
        final String rationale = preceding
            .sublist(first)
            .map((RustCommentRange range) => range.text)
            .join('\n');
        if (_isSafetyComment(rationale)) return true;
      }
    }

    final Iterable<RustCommentRange> inside = commentRanges.where(
      (RustCommentRange range) =>
          range.start > openBrace &&
          range.start < source.length &&
          source.substring(openBrace + 1, range.start).trim().isEmpty,
    );
    return inside.isNotEmpty && _isSafetyComment(inside.first.text);
  }

  /// Returns the matching closing parenthesis in masked source, or -1.
  int matchingParenthesis(int open) {
    if (open < 0 || open >= masked.length || masked[open] != '(') return -1;
    var depth = 0;
    for (var index = open; index < masked.length; index++) {
      if (masked[index] == '(') {
        depth++;
      } else if (masked[index] == ')' && --depth == 0) {
        return index;
      }
    }
    return -1;
  }
}

final class RustCommentRange {
  const RustCommentRange({
    required this.start,
    required this.end,
    required this.text,
  });

  final int start;
  final int end;
  final String text;
}

bool _isSafetyComment(String text) => cachedRegExp(
  r'\bSAFETY\s*:\s*\S',
  caseSensitive: false,
).hasMatch(text.replaceAll(RegExp(r'^\s*(?://+|/\*+|\*+|\*/)'), '').trim());

bool _testOnly(String line) =>
    cachedRegExp(
      r'#\s*\[\s*cfg\s*\([^\n]*\btest\b[^\n]*\)\s*\]',
    ).hasMatch(line) ||
    cachedRegExp(r'#\s*\[\s*test\s*\]').hasMatch(line);

Set<int> _attributedLines(
  List<String> lines,
  bool Function(String line) matchesAttribute,
) {
  final Set<int> result = <int>{};
  var pending = false;
  var depth = 0;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    if (depth > 0) {
      result.add(index);
      depth += '{'.allMatches(line).length - '}'.allMatches(line).length;
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
      depth = '{'.allMatches(line).length - '}'.allMatches(line).length;
      pending = false;
    }
  }
  return result;
}

final class _RustScan {
  const _RustScan({
    required this.masked,
    required this.commentsMasked,
    required this.comments,
  });

  final String masked;
  final String commentsMasked;
  final List<RustCommentRange> comments;
}

_RustScan _scanRust(String source) {
  final StringBuffer masked = StringBuffer();
  final StringBuffer commentsMasked = StringBuffer();
  final List<RustCommentRange> comments = <RustCommentRange>[];
  var index = 0;
  while (index < source.length) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    if (character == '/' && next == '/') {
      final int start = index;
      final int end = source.indexOf('\n', index);
      final int stop = end == -1 ? source.length : end;
      comments.add(
        RustCommentRange(
          start: start,
          end: stop,
          text: source.substring(start, stop),
        ),
      );
      while (index < stop) {
        masked.write(' ');
        commentsMasked.write(' ');
        index++;
      }
      continue;
    }
    if (character == '/' && next == '*') {
      final int start = index;
      var depth = 0;
      do {
        final String current = source[index];
        final String following = index + 1 < source.length
            ? source[index + 1]
            : '';
        if (current == '/' && following == '*') depth++;
        if (current == '*' && following == '/') depth--;
        masked.write(current == '\n' ? '\n' : ' ');
        commentsMasked.write(current == '\n' ? '\n' : ' ');
        index++;
        if ((current == '/' && following == '*') ||
            (current == '*' && following == '/')) {
          masked.write(' ');
          commentsMasked.write(' ');
          index++;
        }
      } while (index < source.length && depth > 0);
      comments.add(
        RustCommentRange(
          start: start,
          end: index,
          text: source.substring(start, index),
        ),
      );
      continue;
    }
    final _LiteralEnd? literal = _rustLiteral(source, index);
    if (literal != null) {
      for (var offset = index; offset < literal.end; offset++) {
        final String value = source[offset];
        masked.write(value == '\n' ? '\n' : ' ');
        commentsMasked.write(value);
      }
      index = literal.end;
      continue;
    }
    masked.write(character);
    commentsMasked.write(character);
    index++;
  }
  return _RustScan(
    masked: masked.toString(),
    commentsMasked: commentsMasked.toString(),
    comments: comments,
  );
}

final class _LiteralEnd {
  const _LiteralEnd(this.end);
  final int end;
}

_LiteralEnd? _rustLiteral(String source, int start) {
  var prefix = start;
  if (source.startsWith('br', start) || source.startsWith('rb', start)) {
    prefix += 2;
  } else if (source.startsWith('r', start) ||
      source.startsWith('b', start) ||
      source.startsWith('c', start)) {
    prefix++;
  }
  if (prefix < source.length && source[prefix] == '#') {
    var hashes = 0;
    while (prefix + hashes < source.length && source[prefix + hashes] == '#') {
      hashes++;
    }
    final int quote = prefix + hashes;
    if (quote >= source.length ||
        source[quote] != '"' ||
        !(source.startsWith('r', start) ||
            source.startsWith('br', start) ||
            source.startsWith('rb', start))) {
      return null;
    }
    final String terminator = '"${'#' * hashes}';
    final int close = source.indexOf(terminator, quote + 1);
    return _LiteralEnd(close == -1 ? source.length : close + terminator.length);
  }
  if (prefix < source.length && source[prefix] == '"') {
    var index = prefix + 1;
    while (index < source.length) {
      if (source[index] == r'\') {
        index += 2;
      } else if (source[index++] == '"') {
        break;
      }
    }
    return _LiteralEnd(index.clamp(0, source.length));
  }
  if (start < source.length && source[start] == "'") {
    var index = start + 1;
    if (index < source.length && source[index] == r'\') index += 2;
    if (index < source.length &&
        source[index] != '\n' &&
        index + 1 < source.length &&
        source[index + 1] == "'") {
      return _LiteralEnd(index + 2);
    }
  }
  return null;
}
