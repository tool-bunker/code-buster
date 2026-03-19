// C# projects need namespace-aware dependency and function facts before shared graph and complexity checks can run.

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// C# type-owner dependencies, functions, and opt-in convention/security rules.
final class CSharpAdapter {
  /// Resolves references to project-owned C# type declarations.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Map<String, String> owners = <String, String>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      for (final RegExpMatch match in _typeDeclaration.allMatches(
        entry.value,
      )) {
        owners.putIfAbsent(match.group(1)!, () => entry.key);
      }
    }
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final MapEntry<String, String> entry in sources.entries) {
      final Set<String> dependencies = <String>{};
      final Set<String> referencedNames = RegExp(r'\b[A-Za-z_]\w*\b')
          .allMatches(entry.value)
          .map((RegExpMatch match) => match.group(0)!)
          .toSet();
      for (final String name in referencedNames) {
        final String? owner = owners[name];
        if (owner != null && owner != entry.key) dependencies.add(owner);
      }
      edges[entry.key] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts brace-delimited C# methods for complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String candidate = lines[index].trimLeft();
        if (!lines[index].contains('(') ||
            candidate.startsWith('//') ||
            candidate.startsWith('/*') ||
            candidate.startsWith('*') ||
            candidate.startsWith('where ') ||
            _typeDeclaration.hasMatch(candidate) ||
            _control.hasMatch(candidate)) {
          continue;
        }
        var signatureEnd = index;
        var signature = lines[index];
        while (!signature.contains('{') &&
            !signature.contains(';') &&
            !signature.contains('=>') &&
            signatureEnd + 1 < lines.length &&
            signatureEnd - index < 12) {
          signatureEnd++;
          signature = '$signature\n${lines[signatureEnd]}';
        }
        final List<RegExpMatch> matches = _method
            .allMatches(signature)
            .toList(growable: false);
        if (matches.isEmpty) continue;
        final RegExpMatch match = matches.last;
        var depth = 0;
        var started = false;
        var end = signatureEnd;
        for (end = index; end < lines.length; end++) {
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

  static final RegExp _typeDeclaration = RegExp(
    r'\b(?:(?:public|internal|private|protected)\s+)?(?:(?:static|sealed|abstract|partial)\s+)*(?:class|interface|struct|enum|record)\s+([A-Za-z_]\w*)',
  );
  static final RegExp _method = RegExp(
    r'(?:^|\s)(?!(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|unsafe|extern|partial|new|extension|bool|byte|char|decimal|double|float|int|long|object|sbyte|short|string|uint|ulong|ushort|void)\s*\()([A-Za-z_]\w*)\s*(?:<[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*>)?\s*\([^;{}]*\)\s*(?:where[^{}]+)?\{',
  );
  static final RegExp _control = RegExp(
    r'^(?:if|for|foreach|while|switch|catch|using|lock)\b',
  );
}
