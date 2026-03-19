// Java package and import structure is translated here into repository-owned edges and callable regions for downstream checks.

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Java project type dependencies, methods, and opt-in safety rules.
final class JavaAdapter {
  /// Resolves references to classes declared in the analyzed project.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Map<String, String> owners = <String, String>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      for (final RegExpMatch match in _type.allMatches(entry.value)) {
        owners.putIfAbsent(match.group(1)!, () => entry.key);
      }
    }
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> source in sources.entries) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch token in _identifier.allMatches(source.value)) {
        final String? owner = owners[token.group(0)!];
        if (owner != null && owner != source.key) dependencies.add(owner);
      }
      edges[source.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts Java methods for language-neutral complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String declarationLine = lines[index].trimLeft().replaceFirst(
          RegExp(r'^(?:}\s*)+(?:else\s+)?'),
          '',
        );
        final RegExpMatch? match = _method.firstMatch(declarationLine);
        if (match == null || _control.hasMatch(declarationLine)) {
          continue;
        }
        var depth = 0;
        var started = false;
        var end = index;
        for (; end < lines.length; end++) {
          depth += '{'.allMatches(lines[end]).length;
          depth -= '}'.allMatches(lines[end]).length;
          started = started || lines[end].contains('{');
          if (started && depth <= 0) break;
        }
        result.add(
          FunctionSource(
            path: entry.key,
            name: match.group(1)!,
            line: index + 1,
            source: lines
                .sublist(index, (end + 1).clamp(0, lines.length))
                .join('\n'),
          ),
        );
        index = end;
      }
    }
    return result;
  }

  static final RegExp _type = RegExp(
    r'\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)',
  );
  static final RegExp _identifier = RegExp(r'\b[A-Za-z_]\w*\b');
  static final RegExp _method = RegExp(
    r'(?:^|\s)([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{',
  );
  static final RegExp _control = RegExp(
    r'^(?:if|for|while|switch|catch|try|synchronized)\b',
  );
}
