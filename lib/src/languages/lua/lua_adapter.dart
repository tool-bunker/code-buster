// Lua dependencies often hide in require and dofile calls; this adapter resolves the literal forms that can be trusted statically.

import 'package:path/path.dart' as path;

import '../../graph/graph.dart';

/// Resolves local Lua and Luau `require` dependencies.
final class LuaGraphAdapter {
  /// Builds a dependency graph from project-relative Lua-family [sources].
  DependencyGraph build(Map<String, String> sources) {
    final Set<String> knownFiles = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    final Map<String, Iterable<String>> cycleEdges =
        <String, Iterable<String>>{};
    final List<String> files = sources.keys.toList()..sort();
    for (final String sourcePath in files) {
      final Set<String> dependencies = <String>{};
      final Set<String> loadTimeDependencies = <String>{};
      final String source = sources[sourcePath]!;
      final String code = _maskNonCode(source);
      final Map<String, String> robloxAliases = _robloxAliases(
        sourcePath,
        code,
      );
      final Set<int> loadTimeRequireOffsets = _loadTimeCallOffsets(
        source,
        code,
        _requirePattern,
        'require',
      );
      final Set<int> loadTimeRobloxRequireOffsets = _loadTimeCallOffsets(
        source,
        code,
        _robloxRequirePattern,
        'require',
      );
      final Set<int> loadTimeDofileOffsets = _loadTimeCallOffsets(
        source,
        code,
        _pathsDofilePattern,
        'paths.dofile',
      );
      for (final RegExpMatch match in _requirePattern.allMatches(source)) {
        if (!_isCallInCode(code, match.start, 'require')) continue;
        final String? target = _resolve(
          sourcePath,
          match.group(1)!,
          knownFiles,
        );
        if (target != null) {
          dependencies.add(target);
          if (loadTimeRequireOffsets.contains(match.start)) {
            loadTimeDependencies.add(target);
          }
        }
      }
      for (final RegExpMatch match in _robloxRequirePattern.allMatches(
        source,
      )) {
        if (!_isCallInCode(code, match.start, 'require')) continue;
        final String? target = _resolveRoblox(
          sourcePath,
          match.group(1)!,
          robloxAliases,
          knownFiles,
        );
        if (target != null) {
          dependencies.add(target);
          if (loadTimeRobloxRequireOffsets.contains(match.start)) {
            loadTimeDependencies.add(target);
          }
        }
      }
      for (final RegExpMatch match in _pathsDofilePattern.allMatches(source)) {
        if (!_isCallInCode(code, match.start, 'paths.dofile')) continue;
        final String? target = _resolveDofile(
          sourcePath,
          match.group(1)!,
          knownFiles,
        );
        if (target != null) {
          dependencies.add(target);
          if (loadTimeDofileOffsets.contains(match.start)) {
            loadTimeDependencies.add(target);
          }
        }
      }
      edges[sourcePath] = dependencies;
      cycleEdges[sourcePath] = loadTimeDependencies;
    }
    return DependencyGraph(edges, cycleEdges: cycleEdges);
  }

  static final RegExp _requirePattern = RegExp(
    r'''\brequire\s*(?:\(\s*)?['"]([^'"]+)['"]\s*\)?''',
  );

  static final RegExp _robloxRequirePattern = RegExp(
    r'\brequire\s*(?:\(\s*)?((?:script|[A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*)+)\s*\)?',
  );

  static final RegExp _robloxAliasPattern = RegExp(
    r'\blocal\s+([A-Za-z_]\w*)\s*=\s*(script(?:\s*\.\s*[A-Za-z_]\w*)*)',
  );

  static final RegExp _pathsDofilePattern = RegExp(
    r'''(?<![\w.:])paths\.dofile\s*\(\s*['"]([^'"]+)['"]\s*\)''',
  );

  static final RegExp _blockKeywordPattern = RegExp(
    r'\b(function|if|for|while|repeat|do|end|until)\b',
  );

  Set<int> _loadTimeCallOffsets(
    String source,
    String code,
    RegExp callPattern,
    String callName,
  ) {
    final List<RegExpMatch> calls = callPattern
        .allMatches(source)
        .where(
          (RegExpMatch match) => _isCallInCode(code, match.start, callName),
        )
        .toList(growable: false);
    final List<RegExpMatch> keywords = _blockKeywordPattern
        .allMatches(code)
        .toList(growable: false);
    final Set<int> result = <int>{};
    final List<bool> blocks = <bool>[];
    var functionDepth = 0;
    var pendingLoopDo = 0;
    var callIndex = 0;
    var keywordIndex = 0;

    while (callIndex < calls.length || keywordIndex < keywords.length) {
      final RegExpMatch? call = callIndex < calls.length
          ? calls[callIndex]
          : null;
      final RegExpMatch? keyword = keywordIndex < keywords.length
          ? keywords[keywordIndex]
          : null;
      if (call != null && (keyword == null || call.start < keyword.start)) {
        if (functionDepth == 0) {
          result.add(call.start);
        }
        callIndex++;
        continue;
      }

      switch (keyword!.group(1)) {
        case 'function':
          blocks.add(true);
          functionDepth++;
        case 'if':
        case 'repeat':
          blocks.add(false);
        case 'for':
        case 'while':
          blocks.add(false);
          pendingLoopDo++;
        case 'do':
          if (pendingLoopDo > 0) {
            pendingLoopDo--;
          } else {
            blocks.add(false);
          }
        case 'end':
        case 'until':
          if (blocks.isNotEmpty && blocks.removeLast()) {
            functionDepth--;
          }
      }
      keywordIndex++;
    }
    return result;
  }

  bool _isCallInCode(String code, int start, String callName) =>
      code.substring(start, start + callName.length) == callName;

  String _maskNonCode(String source) {
    final List<String> masked = source.split('');
    var index = 0;
    while (index < source.length) {
      final String char = source[index];
      if (char == '-' &&
          index + 1 < source.length &&
          source[index + 1] == '-') {
        final int equals = _longBracketEqualsAt(source, index + 2);
        if (equals >= 0) {
          final int end = _longBracketEnd(source, index + 2, equals);
          _maskRange(masked, source, index, end);
          index = end;
          continue;
        }
        final int newline = source.indexOf('\n', index + 2);
        final int end = newline < 0 ? source.length : newline;
        _maskRange(masked, source, index, end);
        index = end;
        continue;
      }
      if (char == "'" || char == '"') {
        final String quote = char;
        var end = index + 1;
        while (end < source.length) {
          if (source[end] == r'\' && end + 1 < source.length) {
            end += 2;
            continue;
          }
          if (source[end++] == quote) break;
        }
        _maskRange(masked, source, index, end);
        index = end;
        continue;
      }
      final int equals = _longBracketEqualsAt(source, index);
      if (equals >= 0) {
        final int end = _longBracketEnd(source, index, equals);
        _maskRange(masked, source, index, end);
        index = end;
        continue;
      }
      index++;
    }
    return masked.join();
  }

  int _longBracketEqualsAt(String source, int start) {
    if (start >= source.length || source[start] != '[') return -1;
    var index = start + 1;
    while (index < source.length && source[index] == '=') {
      index++;
    }
    return index < source.length && source[index] == '['
        ? index - start - 1
        : -1;
  }

  int _longBracketEnd(String source, int start, int equals) {
    final String close = ']${List<String>.filled(equals, '=').join()}]';
    final int end = source.indexOf(close, start + equals + 2);
    return end < 0 ? source.length : end + close.length;
  }

  void _maskRange(List<String> masked, String source, int start, int end) {
    for (var index = start; index < end; index++) {
      if (source[index] != '\n' && source[index] != '\r') {
        masked[index] = ' ';
      }
    }
  }

  String? _resolve(String sourcePath, String module, Set<String> knownFiles) {
    final List<String> bases;
    if (module.startsWith('.')) {
      bases = <String>[
        path.posix.normalize(
          path.posix.join(path.posix.dirname(sourcePath), module),
        ),
      ];
    } else {
      final String modulePath = module.replaceAll('.', '/');
      bases = <String>[modulePath, 'lua/$modulePath'];
    }

    for (final String base in bases) {
      for (final String candidate in <String>[
        base,
        for (final String extension in _extensions) '$base$extension',
        for (final String extension in _extensions) '$base/init$extension',
      ]) {
        if (knownFiles.contains(candidate)) {
          return candidate;
        }
      }
    }
    return null;
  }

  Map<String, String> _robloxAliases(String sourcePath, String code) {
    final Map<String, String> aliases = <String, String>{};
    for (final RegExpMatch match in _robloxAliasPattern.allMatches(code)) {
      final String? base = _robloxExpressionBase(
        sourcePath,
        match.group(2)!,
        const <String, String>{},
      );
      if (base != null) {
        aliases[match.group(1)!] = base;
      }
    }
    return aliases;
  }

  String? _resolveRoblox(
    String sourcePath,
    String expression,
    Map<String, String> aliases,
    Set<String> knownFiles,
  ) {
    final String? base = _robloxExpressionBase(sourcePath, expression, aliases);
    if (base == null) return null;
    for (final String candidate in <String>[
      base,
      for (final String extension in _extensions) '$base$extension',
      for (final String extension in _extensions) '$base/init$extension',
    ]) {
      if (knownFiles.contains(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  String? _robloxExpressionBase(
    String sourcePath,
    String expression,
    Map<String, String> aliases,
  ) {
    final List<String> segments = expression
        .split(RegExp(r'\s*\.\s*'))
        .toList(growable: false);
    final String? initialBase = segments.first == 'script'
        ? _robloxScriptBase(sourcePath)
        : aliases[segments.first];
    if (initialBase == null) return null;
    var base = initialBase;
    for (final String segment in segments.skip(1)) {
      base = segment == 'Parent'
          ? path.posix.dirname(base)
          : path.posix.join(base, segment);
    }
    return path.posix.normalize(base);
  }

  String _robloxScriptBase(String sourcePath) {
    final String directory = path.posix.dirname(sourcePath);
    final String fileName = path.posix.basename(sourcePath);
    final String extension = _extensions.firstWhere(
      fileName.endsWith,
      orElse: () => '',
    );
    var scriptName = extension.isEmpty
        ? fileName
        : fileName.substring(0, fileName.length - extension.length);
    for (final String suffix in const <String>['.server', '.client']) {
      if (scriptName.endsWith(suffix)) {
        scriptName = scriptName.substring(0, scriptName.length - suffix.length);
        break;
      }
    }
    return scriptName == 'init'
        ? directory
        : path.posix.join(directory, scriptName);
  }

  String? _resolveDofile(
    String sourcePath,
    String targetPath,
    Set<String> knownFiles,
  ) {
    final String candidate = path.posix.normalize(
      path.posix.join(path.posix.dirname(sourcePath), targetPath),
    );
    return knownFiles.contains(candidate) ? candidate : null;
  }

  static const List<String> _extensions = <String>['.lua', '.luau'];
}
