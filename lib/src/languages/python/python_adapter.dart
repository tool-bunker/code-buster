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
        _runtimeImportSource(sources[sourcePath]!),
      )) {
        final String? fromModule = match.group(1);
        final List<String> modules;
        if (fromModule == null) {
          modules = <String>[match.group(3)!];
        } else {
          final String importedName = match.group(2)!;
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
          final String? target = _resolve(sourcePath, module, knownFiles);
          if (target != null) {
            dependencies.add(target);
            break;
          }
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

  String _runtimeImportSource(String source) {
    final String code = _maskNonCode(source);
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
          RegExp(r'^(?:async\s+def|def|class)\s+').hasMatch(trimmed) ||
          RegExp(r'^if\s+(?:typing\.)?TYPE_CHECKING\s*:').hasMatch(trimmed);
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

  String _maskNonCode(String source) {
    final List<int> result = source.codeUnits.toList();
    String? quote;
    var tripleQuoted = false;
    var escaped = false;
    var inComment = false;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      final String next = index + 1 < source.length ? source[index + 1] : '';
      final String nextTwo = index + 2 < source.length
          ? source.substring(index, index + 3)
          : '';
      if (inComment) {
        if (character == '\n') {
          inComment = false;
        } else {
          result[index] = 0x20;
        }
        continue;
      }
      if (quote != null) {
        if (character != '\n' && character != '\r') {
          result[index] = 0x20;
        }
        if (tripleQuoted && nextTwo == quote * 3) {
          result[index + 1] = 0x20;
          result[index + 2] = 0x20;
          index += 2;
          quote = null;
          tripleQuoted = false;
        } else if (!tripleQuoted && !escaped && character == quote) {
          quote = null;
        }
        escaped = !tripleQuoted && !escaped && character == r'\';
        if (character != r'\') {
          escaped = false;
        }
        continue;
      }
      if (character == '#') {
        result[index] = 0x20;
        inComment = true;
      } else if (character == '"' || character == "'") {
        quote = character;
        tripleQuoted =
            next == character &&
            index + 2 < source.length &&
            source[index + 2] == character;
        result[index] = 0x20;
        if (tripleQuoted) {
          result[index + 1] = 0x20;
          result[index + 2] = 0x20;
          index += 2;
        }
      }
    }
    return String.fromCharCodes(result);
  }

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
