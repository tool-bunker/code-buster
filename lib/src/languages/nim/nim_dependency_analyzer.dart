// Nim module names can expand into grouped and relative imports, so dependency resolution is kept separate from procedure extraction.

import 'package:path/path.dart' as path;

import '../../graph/graph.dart';

/// Resolves project-local Nim import, include, and from-import dependencies.
final class NimDependencyAnalyzer {
  /// Builds a local dependency graph for [sources].
  DependencyGraph build(Map<String, String> sources) {
    final Set<String> known = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final String sourcePath in sources.keys.toList()..sort()) {
      final Set<String> dependencies = <String>{};
      for (final String raw in sources[sourcePath]!.split('\n')) {
        final String line = _withoutComment(raw).trim();
        for (final String module in _modules(line)) {
          if (module.startsWith('std/') || module.startsWith('pkg/')) continue;
          final String? resolved = _resolve(sourcePath, module, known);
          if (resolved != null) dependencies.add(resolved);
        }
      }
      edges[sourcePath] = dependencies;
    }
    return DependencyGraph(edges);
  }

  Iterable<String> _modules(String line) sync* {
    String body;
    if (line.startsWith('import ') || line.startsWith('include ')) {
      body = line.substring(line.indexOf(' ') + 1);
    } else if (line.startsWith('from ') && line.contains(' import ')) {
      body = line.substring(5, line.indexOf(' import '));
    } else {
      return;
    }
    final RegExpMatch? bracket = RegExp(
      r'^([^\[]*)\[([^]]+)\]',
    ).firstMatch(body);
    if (bracket != null) {
      final String prefix = bracket.group(1)!.trim();
      for (final String item in bracket.group(2)!.split(',')) {
        yield '$prefix${item.trim()}'.replaceAll('.', '/');
      }
      return;
    }
    for (final String item in body.split(',')) {
      final String module = item.trim().split(RegExp(r'\s+as\s+')).first;
      if (module.isNotEmpty) {
        yield module.startsWith('.') || module.contains('/')
            ? module
            : module.replaceAll('.', '/');
      }
    }
  }

  String? _resolve(String sourcePath, String module, Set<String> known) {
    final String clean = module.replaceAll('"', '').replaceAll("'", '');
    final String relative = path.posix.normalize(
      path.posix.join(path.posix.dirname(sourcePath), clean),
    );
    for (final String candidate in <String>[
      relative,
      '$relative.nim',
      '$relative.nims',
      clean,
      '$clean.nim',
      '$clean.nims',
    ]) {
      if (known.contains(candidate)) return candidate;
    }
    return null;
  }

  String _withoutComment(String line) {
    var quote = '';
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      if ((character == '"' || character == "'") &&
          (index == 0 || line[index - 1] != r'\')) {
        quote = quote.isEmpty ? character : (quote == character ? '' : quote);
      } else if (character == '#' && quote.isEmpty) {
        return line.substring(0, index);
      }
    }
    return line;
  }
}
