// Wren has a compact module and method syntax that still needs explicit extraction for graph and function-based checks.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Wren imports, method extraction, and opt-in safety/style checks.
final class WrenAdapter {
  /// Resolves local `import "module"` dependencies.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Set<String> known = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _import.allMatches(entry.value)) {
        final String? target = _resolve(entry.key, match.group(1)!, known);
        if (target != null) dependencies.add(target);
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts brace-delimited Wren methods and top-level functions.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? match = _method.firstMatch(lines[index]);
        if (match == null || _control.hasMatch(lines[index].trimLeft())) {
          continue;
        }
        var depth = 0;
        var end = index;
        for (; end < lines.length; end++) {
          depth += '{'.allMatches(lines[end]).length;
          depth -= '}'.allMatches(lines[end]).length;
          if (depth <= 0 && end > index) break;
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

  String? _resolve(String sourcePath, String module, Set<String> known) {
    final String base = path.posix.normalize(
      path.posix.join(path.posix.dirname(sourcePath), module),
    );
    for (final String candidate in <String>[
      base,
      '$base.wren',
      module,
      '$module.wren',
    ]) {
      if (known.contains(candidate)) return candidate;
    }
    return null;
  }

  static final RegExp _import = RegExp(
    r'''^\s*import\s+["']([^"']+)["']''',
    multiLine: true,
  );
  static final RegExp _method = RegExp(
    r'^\s*(?:static\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{',
  );
  static final RegExp _control = RegExp(r'^(?:if|for|while)\b');
}
