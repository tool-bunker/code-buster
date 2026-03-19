// Go imports, receivers, tests, and module paths follow conventions that are best resolved once before rules inspect them.

import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Go module imports, function extraction, and high-confidence safety checks.
final class GoAdapter {
  /// Resolves imports belonging to the repository's own Go module.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final String module = _moduleName(sources['go.mod'] ?? '');
    final Map<String, List<String>> filesByDirectory = <String, List<String>>{};
    // Imported Go packages are compiled without their `_test.go` files. Keeping
    // external test packages in the target set creates artificial file cycles
    // when a test imports the package under test through a helper package.
    for (final String sourcePath in sources.keys.where(
      (String p) => p.endsWith('.go') && !p.endsWith('_test.go'),
    )) {
      filesByDirectory
          .putIfAbsent(path.posix.dirname(sourcePath), () => <String>[])
          .add(sourcePath);
    }
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      if (!entry.key.endsWith('.go')) continue;
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _import.allMatches(entry.value)) {
        final String imported = match.group(1)!;
        if (module.isEmpty ||
            (imported != module && !imported.startsWith('$module/'))) {
          continue;
        }
        final String directory = imported == module
            ? '.'
            : imported.substring(module.length + 1);
        dependencies.addAll(
          (filesByDirectory[directory] ?? const <String>[]).where(
            (String target) => target != entry.key,
          ),
        );
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts brace-delimited Go functions and methods.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      if (!entry.key.endsWith('.go')) continue;
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? declaration = _function.firstMatch(lines[index]);
        if (declaration == null) continue;
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
            name: declaration.group(1)!,
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

  static String _moduleName(String source) =>
      RegExp(
        r'^\s*module\s+(\S+)',
        multiLine: true,
      ).firstMatch(source)?.group(1) ??
      '';

  static final RegExp _import = RegExp(r'''["']([^"']+)["']''');
  static final RegExp _function = RegExp(
    r'^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(',
  );
}
