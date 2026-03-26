// Complexity and duplication need accurate Nim procedure bodies, including multiline declarations and nested constructs.

import '../../engine/analysis.dart';

/// Extracts indentation-delimited Nim callable bodies.
final class NimFunctionParser {
  /// Extracts proc, func, method, and iterator bodies from [sources].
  List<FunctionSource> parse(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? declaration = _procedure.firstMatch(lines[index]);
        if (declaration == null) continue;
        final int indent = _indent(lines[index]);
        var end = index + 1;
        while (end < lines.length) {
          final String candidate = lines[end];
          if (candidate.trim().isNotEmpty && _indent(candidate) <= indent) {
            break;
          }
          end++;
        }
        result.add(
          FunctionSource(
            path: entry.key,
            name: declaration.group(1)!,
            line: index + 1,
            source: lines.sublist(index, end).join('\n'),
          ),
        );
        index = end - 1;
      }
    }
    return List<FunctionSource>.unmodifiable(result);
  }

  int _indent(String line) {
    var result = 0;
    for (final int rune in line.runes) {
      if (rune == 32) {
        result++;
      } else if (rune == 9) {
        result += 2;
      } else {
        break;
      }
    }
    return result;
  }

  static final RegExp _procedure = RegExp(
    r'^\s*(?:proc|func|method|iterator)\s+`?([A-Za-z_]\w*)`?\*?\s*(?:\[[^]]*\])?\s*\(',
  );
}
