// Mojo uses Python-like modules and indentation, so a focused adapter can provide repository edges and callable regions without pretending Python syntax is identical.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Extracts Mojo imports and indentation-delimited functions.
final class MojoAdapter {
  /// Resolves local `import` and `from ... import` statements.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Map<String, List<String>> owners = <String, List<String>>{};
    for (final String sourcePath in sources.keys) {
      final String stem = path.posix.basenameWithoutExtension(sourcePath);
      owners.putIfAbsent(stem, () => <String>[]).add(sourcePath);
    }

    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _import.allMatches(entry.value)) {
        final String module = (match.group(1) ?? match.group(2)!)
            .split('.')
            .last;
        final List<String> candidates = owners[module] ?? const <String>[];
        if (candidates.length == 1 && candidates.single != entry.key) {
          dependencies.add(candidates.single);
        }
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts top-level and struct methods for complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? match = _function.firstMatch(lines[index]);
        if (match == null) continue;
        final int indentation = _indentation(lines[index]);
        var end = index + 1;
        while (end < lines.length) {
          final String line = lines[end];
          if (line.trim().isNotEmpty && _indentation(line) <= indentation) {
            break;
          }
          end++;
        }
        result.add(
          FunctionSource(
            path: entry.key,
            name: match.group(1)!,
            line: index + 1,
            source: lines.sublist(index, end).join('\n'),
          ),
        );
        index = end - 1;
      }
    }
    return result;
  }

  static int _indentation(String line) => line.length - line.trimLeft().length;

  static final RegExp _import = RegExp(
    r'^\s*(?:import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)|from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+)',
    multiLine: true,
  );
  static final RegExp _function = RegExp(
    r'^\s*def\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\([^)]*\)[^:]*:',
  );
}
