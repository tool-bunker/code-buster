// Python imports and indentation-defined functions are converted into repository edges and callable regions without executing the code.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Resolves local Python imports into language-neutral graph edges.
final class PythonGraphAdapter {
  /// Builds a dependency graph from project-relative Python [sources].
  DependencyGraph build(Map<String, String> sources) {
    final Set<String> knownFiles = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    final List<String> files = sources.keys.toList()..sort();
    for (final String sourcePath in files) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _importPattern.allMatches(
        sources[sourcePath]!,
      )) {
        final String? fromModule = match.group(1);
        final String module = fromModule == null
            ? match.group(3)!
            : fromModule == '.'
            ? '.${match.group(2)!}'
            : fromModule;
        final String? target = _resolve(sourcePath, module, knownFiles);
        if (target != null) {
          dependencies.add(target);
        }
      }
      edges[sourcePath] = dependencies;
    }
    return DependencyGraph(edges);
  }

  static final RegExp _importPattern = RegExp(
    r'^\s*(?:from\s+([.\w]+)\s+import\s+([A-Za-z_]\w*|\*)|import\s+([\w.]+))',
    multiLine: true,
  );

  String? _resolve(String sourcePath, String module, Set<String> knownFiles) {
    final String relative;
    if (module.startsWith('.')) {
      final int dots =
          module.length - module.replaceFirst(RegExp(r'^\.+'), '').length;
      final List<String> base = path.posix.dirname(sourcePath).split('/');
      final int keep = (base.length - dots + 1).clamp(0, base.length);
      final String suffix = module.substring(dots).replaceAll('.', '/');
      relative = path.posix.normalize(
        path.posix.joinAll(<String>[...base.take(keep), suffix]),
      );
    } else {
      relative = module.replaceAll('.', '/');
    }
    for (final String candidate in <String>[
      '$relative.py',
      '$relative/__init__.py',
    ]) {
      if (knownFiles.contains(candidate)) {
        return candidate;
      }
    }
    return null;
  }
}

/// Extracts indentation-scoped Python functions for language-neutral metrics.
final class PythonFunctionParser {
  /// Parses named Python functions from [sources].
  List<FunctionSource> parse(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String sourcePath in paths) {
      final List<String> lines = sources[sourcePath]!.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? match = _declaration.firstMatch(lines[index]);
        if (match == null) {
          continue;
        }
        final int indent = lines[index].length - lines[index].trimLeft().length;
        var end = index + 1;
        while (end < lines.length &&
            (lines[end].trim().isEmpty ||
                lines[end].length - lines[end].trimLeft().length > indent)) {
          end++;
        }
        result.add(
          FunctionSource(
            path: sourcePath,
            name: match.group(1)!,
            line: index + 1,
            source: lines.sublist(index, end).join('\n'),
          ),
        );
      }
    }
    return List<FunctionSource>.unmodifiable(result);
  }

  static final RegExp _declaration = RegExp(
    r'^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*\(',
  );
}
