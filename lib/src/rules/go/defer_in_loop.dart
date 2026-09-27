// A defer inside a Go loop accumulates work until the owning function returns,
// unless a nested function scopes that defer to one iteration.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';

/// Reports Go `defer` statements lexically nested in loops.
final class GoDeferInLoopRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoDeferInLoopRule()
    : super(
        const RuleMetadata(
          id: 'go-defer-in-loop',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Avoid defer inside long-running loops',
          why:
              'Deferred calls accumulate until the surrounding function returns.',
          suggestion:
              'Extract one iteration into a function or release resources explicitly.',
          languages: <String>['go'],
          version: 4,
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      final List<_GoScope> scopes = <_GoScope>[];
      final List<String> lines = _goStructure(source.value).split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        final int firstCode = line.indexOf(cachedRegExp(r'\S'));
        final int deferOffset =
            cachedRegExp(r'\bdefer\b').firstMatch(line)?.start ?? -1;
        if (deferOffset >= 0 && deferOffset == firstCode) {
          final int loop = scopes.lastIndexOf(_GoScope.loop);
          final int function = scopes.lastIndexOf(_GoScope.function);
          if (loop > function &&
              !_exitsLoopAfter(lines, index, scopes.length - loop - 1)) {
            yield report(
              context,
              path: source.key,
              line: index + 1,
              message:
                  'defer inside a loop accumulates until the surrounding function returns',
              confidence: 'high',
            );
          }
        }

        var segmentStart = 0;
        for (var offset = 0; offset < line.length; offset++) {
          switch (line[offset]) {
            case '}':
              if (scopes.isNotEmpty) scopes.removeLast();
              segmentStart = offset + 1;
            case '{':
              final String prefix = line.substring(segmentStart, offset);
              scopes.add(
                cachedRegExp(r'(?:^|\W)for(?:\s|$)').hasMatch(prefix)
                    ? _GoScope.loop
                    : cachedRegExp(r'\bfunc\s*\(').hasMatch(prefix)
                    ? _GoScope.function
                    : _GoScope.block,
              );
              segmentStart = offset + 1;
          }
        }
      }
    }
  }
}

enum _GoScope { block, function, loop }

bool _exitsLoopAfter(List<String> lines, int deferLine, int nestedBlockDepth) {
  var depth = nestedBlockDepth;
  for (var index = deferLine; index < lines.length; index++) {
    final String line = lines[index];
    final int start = index == deferLine
        ? (cachedRegExp(r'\bdefer\b').firstMatch(line)?.end ?? 0)
        : 0;
    if (depth <= nestedBlockDepth &&
        cachedRegExp(
          r'^\s*(?:return\b|break\b|continue\b|goto\b)',
        ).hasMatch(line)) {
      return true;
    }
    for (var offset = start; offset < line.length; offset++) {
      switch (line[offset]) {
        case '{':
          depth++;
        case '}':
          if (depth == 0) return false;
          depth--;
      }
    }
  }
  return false;
}

String _goStructure(String source) {
  final StringBuffer result = StringBuffer();
  var inBlockComment = false;
  var inLineComment = false;
  String? quote;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    if (inLineComment) {
      result.write(character == '\n' ? '\n' : ' ');
      if (character == '\n') inLineComment = false;
    } else if (inBlockComment) {
      result.write(character == '\n' ? '\n' : ' ');
      if (character == '*' && next == '/') {
        result.write(' ');
        index++;
        inBlockComment = false;
      }
    } else if (quote != null) {
      result.write(character == '\n' ? '\n' : ' ');
      if (quote != '`' && character == r'\' && next.isNotEmpty) {
        result.write(next == '\n' ? '\n' : ' ');
        index++;
      } else if (character == quote) {
        quote = null;
      }
    } else if (character == '/' && next == '/') {
      result.write('  ');
      index++;
      inLineComment = true;
    } else if (character == '/' && next == '*') {
      result.write('  ');
      index++;
      inBlockComment = true;
    } else if (character == '"' || character == "'" || character == '`') {
      result.write(' ');
      quote = character;
    } else {
      result.write(character);
    }
  }
  return result.toString();
}
