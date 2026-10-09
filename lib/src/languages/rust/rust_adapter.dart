// Rust modules and functions need a lightweight repository index before cross-file and complexity checks can reason about them.

import 'package:path/path.dart' as path;

import '../../core/regexp_cache.dart';
import '../../engine/analysis.dart';
import '../../graph/graph.dart';
import 'rust_analysis.dart';

/// Extracts local Rust module edges and brace-delimited functions.
final class RustAdapter {
  /// Resolves `mod` declarations and local `use` paths to discovered Rust files.
  DependencyGraph buildGraph(
    Map<String, String> sources, {
    RustAnalysis? analysis,
  }) {
    final RustAnalysis parsed = analysis ?? RustAnalysis(sources);
    final Set<String> known = sources.keys.toSet();
    final Map<String, List<String>> byStem = <String, List<String>>{};
    for (final String sourcePath in known) {
      byStem.putIfAbsent(_stem(sourcePath), () => <String>[]).add(sourcePath);
    }

    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, RustFileAnalysis> entry
        in parsed.files.entries) {
      final String code = entry.value.masked;
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch declaration in _module.allMatches(code)) {
        final String module = declaration.requiredGroup(1);
        final String directory = path.posix.dirname(entry.key);
        for (final String candidate in <String>[
          path.posix.join(directory, '$module.rs'),
          path.posix.join(directory, module, 'mod.rs'),
        ]) {
          if (known.contains(candidate)) dependencies.add(candidate);
        }
      }
      for (final RegExpMatch import in _use.allMatches(code)) {
        final String module = import.requiredGroup(1);
        final List<String> owners = byStem[module] ?? const <String>[];
        if (owners.length == 1 && owners.single != entry.key) {
          dependencies.add(owners.single);
        }
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts Rust functions for language-neutral complexity analysis.
  List<FunctionSource> functions(
    Map<String, String> sources, {
    RustAnalysis? analysis,
  }) {
    final RustAnalysis parsed = analysis ?? RustAnalysis(sources);
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, RustFileAnalysis> entry
        in parsed.files.entries) {
      final RustFileAnalysis file = entry.value;
      final String code = file.masked;
      final Set<int> testLines = file.testLines;
      for (final RegExpMatch match in _function.allMatches(code)) {
        final RegExpMatch? functionName = cachedRegExp(
          r'\bfn\s+',
        ).firstMatch(match.requiredGroup(0));
        if (functionName == null) {
          throw StateError('Rust function pattern omitted its `fn` keyword');
        }
        final int declarationStart = match.start + functionName.start;
        final int open = code.indexOf('{', match.start);
        final int close = file.matchingBrace(open);
        if (testLines.contains(_lineAt(code, declarationStart) - 1)) continue;
        if (open == -1 || close == -1) continue;
        result.add(
          FunctionSource(
            path: entry.key,
            name: match.requiredGroup(1),
            line: _lineAt(file.source, declarationStart),
            source: file.source.substring(match.start, close + 1),
          ),
        );
      }
    }
    return result;
  }

  static String _stem(String sourcePath) {
    final String name = path.posix.basenameWithoutExtension(sourcePath);
    return name == 'mod'
        ? path.posix.basename(path.posix.dirname(sourcePath))
        : name;
  }

  static final RegExp _module = cachedRegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;',
    multiLine: true,
  );
  static final RegExp _use = cachedRegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:(?:crate|self|super)::)*([A-Za-z_]\w*)',
    multiLine: true,
  );
  static final RegExp _function = cachedRegExp(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\([^;{}]*\)[^{;]*\{',
    multiLine: true,
  );
}

/// Returns zero-based lines belonging to Rust test-only attributed items.
Set<int> rustTestLines(List<String> lines) =>
    RustFileAnalysis(lines.join('\n')).testLines;

int _lineAt(String source, int offset) =>
    1 + '\n'.allMatches(source.substring(0, offset)).length;
