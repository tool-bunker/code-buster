// Python imports and indentation-defined functions are converted into repository edges and callable regions without executing the code.

import 'package:path/path.dart' as path;
import '../../core/regexp_cache.dart';
import '../../engine/analysis.dart';
import '../../graph/graph.dart';
import 'python_source_index.dart';

/// Resolves local Python imports into language-neutral graph edges.
final class PythonGraphAdapter {
  /// Builds a dependency graph from project-relative Python [sources].
  DependencyGraph build(Map<String, String> sources) =>
      buildIndexed(PythonSourceIndex(sources));

  /// Builds a dependency graph from a shared Python [index].
  DependencyGraph buildIndexed(PythonSourceIndex index) {
    final Set<String> knownFiles = index.files
        .map((PythonSourceFacts facts) => facts.path)
        .toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final PythonSourceFacts facts in index.files) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _importPattern.allMatches(
        _runtimeImportSource(facts),
      )) {
        final String? fromModule = match.group(1);
        final List<String> modules;
        if (fromModule == null) {
          modules = <String>[match.requiredGroup(3)];
        } else {
          final String importedName = match.requiredGroup(2);
          final String baseModule = fromModule == '.'
              ? '.$importedName'
              : fromModule;
          modules = <String>[
            if (fromModule != '.' && importedName != '*')
              '$fromModule.$importedName',
            baseModule,
          ];
        }
        for (final String module in modules) {
          final String? target = _resolve(facts.path, module, knownFiles);
          if (target != null) {
            dependencies.add(target);
            break;
          }
        }
      }
      edges[facts.path] = dependencies;
    }
    return DependencyGraph(edges);
  }

  static final RegExp _importPattern = cachedRegExp(
    r'^\s*(?:from\s+([.\w]+)\s+import\s+([A-Za-z_]\w*|\*)|import\s+([\w.]+))',
    multiLine: true,
  );

  String _runtimeImportSource(PythonSourceFacts facts) {
    final String code = facts.maskedSource;
    final List<String> result = <String>[];
    int? excludedBlockIndent;
    for (final String raw in code.split('\n')) {
      final String trimmed = raw.trim();
      final int indent = raw.length - raw.trimLeft().length;
      if (excludedBlockIndent != null &&
          trimmed.isNotEmpty &&
          indent <= excludedBlockIndent) {
        excludedBlockIndent = null;
      }
      final bool startsExcludedBlock =
          cachedRegExp(r'^(?:async\s+def|def|class)\s+').hasMatch(trimmed) ||
          cachedRegExp(
            r'^if\s+(?:typing\.)?TYPE_CHECKING\s*:',
          ).hasMatch(trimmed);
      if (startsExcludedBlock) {
        excludedBlockIndent = indent;
        result.add('');
      } else if (excludedBlockIndent != null && indent > excludedBlockIndent) {
        result.add('');
      } else {
        result.add(raw);
      }
    }
    return result.join('\n');
  }

  String? _resolve(String sourcePath, String module, Set<String> knownFiles) {
    final String relative;
    if (module.startsWith('.')) {
      final int dots =
          module.length - module.replaceFirst(cachedRegExp(r'^\.+'), '').length;
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
  List<FunctionSource> parse(Map<String, String> sources) =>
      parseIndexed(PythonSourceIndex(sources));

  /// Parses named functions from a shared Python [index].
  List<FunctionSource> parseIndexed(PythonSourceIndex index) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final PythonSourceFacts facts in index.files) {
      final List<String> lines = facts.lines;
      for (var lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        final RegExpMatch? match = _declaration.firstMatch(lines[lineIndex]);
        if (match == null) continue;
        final int indent =
            lines[lineIndex].length - lines[lineIndex].trimLeft().length;
        var end = lineIndex + 1;
        while (end < lines.length &&
            (lines[end].trim().isEmpty ||
                lines[end].length - lines[end].trimLeft().length > indent)) {
          end++;
        }
        result.add(
          FunctionSource(
            path: facts.path,
            name: match.group(1)!,
            line: lineIndex + 1,
            source: lines.sublist(lineIndex, end).join('\n'),
          ),
        );
      }
    }
    return List<FunctionSource>.unmodifiable(result);
  }

  static final RegExp _declaration = cachedRegExp(
    r'^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*\(',
  );
}
