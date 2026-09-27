// Lua source checks need string-safe lexical facts and repository context that are cheaper to collect together.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';

/// Shared stateful scan used by independently registered Lua rules.
final class LuaRuleAnalysis {
  /// Emits findings for [ruleId] in source order.
  // code-buster-ignore complex-function: rule-ID dispatch shares Lua block state and executes independent checks in one source pass.
  List<Finding> findings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      final List<String> codeLines = _codeOutsideLuaLongBracketsAndComments(
        lines,
      );
      var blockDepth = 0;
      int? hotFunctionDepth;
      var tableDepth = 0;
      final List<Set<String>> localScopes = <Set<String>>[<String>{}];
      String? pendingBlockTerminator;
      for (var index = 0; index < codeLines.length; index++) {
        final String line = codeLines[index].trim();
        final bool startsHotFunction = _declaresHotFunction(line);
        final bool inHotFunction =
            hotFunctionDepth != null || startsHotFunction;

        void add(String id, RuleSeverity severity, String message) {
          if (id != ruleId) return;
          result.add(
            Finding(
              code: id,
              severity: severity,
              path: entry.key,
              line: index + 1,
              endLine: index + 1,
              message: message,
              confidence: 'medium',
              why: id == 'lua-os-execute'
                  ? 'Shell execution can introduce command injection when command text includes input.'
                  : 'This scripting construct can weaken correctness, security, or runtime performance.',
              suggestion: id == 'lua-os-execute'
                  ? 'Avoid shelling out or validate/allow-list arguments carefully.'
                  : 'Use the safer explicit pattern described by the rule.',
            ),
          );
        }

        final Match? assignment = cachedRegExp(
          r'^([A-Za-z_]\w*)\s*=(?!=)',
        ).firstMatch(line);
        final bool assignsLocal =
            assignment != null &&
            localScopes.any(
              (Set<String> scope) => scope.contains(assignment.group(1)),
            );
        if (tableDepth == 0 &&
            !line.startsWith('local ') &&
            !line.startsWith('function ') &&
            assignment != null &&
            !assignsLocal) {
          add(
            'lua-global-assignment',
            RuleSeverity.warn,
            'possible global assignment',
          );
        }
        final Match? localFunctionDeclaration = cachedRegExp(
          r'\blocal\s+function\s+([A-Za-z_]\w*)\s*\(',
        ).firstMatch(line);
        if (localFunctionDeclaration != null) {
          localScopes.last.add(localFunctionDeclaration.requiredGroup(1));
        }
        if (_usesGlobalDynamicLoad(codeLines, index, line, localScopes)) {
          add(
            'lua-loadstring',
            RuleSeverity.error,
            'dynamic Lua code execution used',
          );
        }
        if (line.contains('os.execute(') || line.contains('io.popen(')) {
          add(
            'lua-os-execute',
            RuleSeverity.warn,
            'shell command execution used',
          );
        }
        if (line.startsWith('pcall(') &&
            (index + 1 >= codeLines.length ||
                const <String>{
                  '',
                  'end',
                  'return',
                }.contains(codeLines[index + 1].trim()))) {
          add(
            'lua-pcall-swallow',
            RuleSeverity.info,
            'pcall result appears ignored',
          );
        }
        if (inHotFunction &&
            (line.contains('print(') || line.contains('warn('))) {
          add(
            'lua-print-in-loop',
            RuleSeverity.info,
            'logging inside update/draw-like function',
          );
        }
        if (inHotFunction &&
            !line.startsWith('type ') &&
            (line.contains(' = {') || line.startsWith('return {'))) {
          add(
            'lua-table-alloc-in-loop',
            RuleSeverity.info,
            'table allocation inside update/draw-like function',
          );
        }
        if (_mutatesIteratedTable(codeLines, index, line)) {
          add(
            'lua-mutate-pairs',
            RuleSeverity.warn,
            'table may be mutated while iterating',
          );
        }

        final Match? localDeclaration = cachedRegExp(
          r'^local\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)(?:\s*=|\s*$)',
        ).firstMatch(line);
        if (localDeclaration != null) {
          localScopes.last.addAll(
            localDeclaration
                .requiredGroup(1)
                .split(',')
                .map((String name) => name.trim()),
          );
        }

        final Match? functionDeclaration = cachedRegExp(
          r'\bfunction\s*(?:[A-Za-z_][\w.:]*)?\s*\(([^)]*)\)',
        ).firstMatch(line);
        final bool completesPendingBlock =
            pendingBlockTerminator != null &&
            cachedRegExp(
              '\\b${RegExp.escape(pendingBlockTerminator)}\\b',
            ).hasMatch(line);
        if (completesPendingBlock) pendingBlockTerminator = null;
        final Match? blockDeclaration = cachedRegExp(
          r'^(if|for|while|repeat)\b',
        ).firstMatch(line);
        final bool opensStandaloneDo = line == 'do' && !completesPendingBlock;
        final bool opensBlock =
            functionDeclaration != null ||
            blockDeclaration != null ||
            opensStandaloneDo;
        if (opensBlock) {
          final Set<String> scope = <String>{};
          if (functionDeclaration != null) {
            scope.addAll(
              functionDeclaration
                  .requiredGroup(1)
                  .split(',')
                  .map((String name) => name.trim())
                  .where(
                    (String name) => cachedRegExp(r'^\w+$').hasMatch(name),
                  ),
            );
          }
          final Match? loopDeclaration = cachedRegExp(
            r'^for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+(?:in\b|=)',
          ).firstMatch(line);
          if (loopDeclaration != null) {
            scope.addAll(
              loopDeclaration
                  .requiredGroup(1)
                  .split(',')
                  .map((String name) => name.trim()),
            );
          }
          localScopes.add(scope);
        }
        if (blockDeclaration != null) {
          final String keyword = blockDeclaration.requiredGroup(1);
          final String terminator = keyword == 'if'
              ? 'then'
              : const <String>{'for', 'while'}.contains(keyword)
              ? 'do'
              : '';
          if (terminator.isNotEmpty &&
              !cachedRegExp('\\b$terminator\\b').hasMatch(line)) {
            pendingBlockTerminator = terminator;
          }
        }
        final int closingScopes =
            cachedRegExp(r'\bend\b').allMatches(line).length +
            (cachedRegExp(r'^until\b').hasMatch(line) ? 1 : 0);
        for (
          var count = 0;
          count < closingScopes && localScopes.length > 1;
          count++
        ) {
          localScopes.removeLast();
        }
        tableDepth += '{'.allMatches(line).length;
        tableDepth -= '}'.allMatches(line).length;
        if (tableDepth < 0) tableDepth = 0;
        final int depthBeforeLine = blockDepth;
        blockDepth += _blockDepthDelta(line);
        if (startsHotFunction) {
          hotFunctionDepth = depthBeforeLine + 1;
        }
        if (hotFunctionDepth != null && blockDepth < hotFunctionDepth) {
          hotFunctionDepth = null;
        }
      }
    }
    return result;
  }

  static bool _usesGlobalDynamicLoad(
    List<String> lines,
    int lineIndex,
    String line,
    List<Set<String>> localScopes,
  ) {
    for (final RegExpMatch match in cachedRegExp(
      r'\b(load(?:string)?)\b',
    ).allMatches(line)) {
      final String name = match.requiredGroup(1);
      if (localScopes.any((Set<String> scope) => scope.contains(name))) {
        continue;
      }

      final String prefix = line.substring(0, match.start).trimRight();
      if (cachedRegExp(r'\bfunction$').hasMatch(prefix) ||
          prefix.endsWith('.') ||
          prefix.endsWith(':')) {
        continue;
      }

      var suffix = line.substring(match.end);
      var nextLine = lineIndex + 1;
      while (suffix.trim().isEmpty && nextLine < lines.length) {
        suffix = _strip(lines[nextLine]).split('--').first;
        nextLine++;
      }
      if (cachedRegExp(r'^\s*\(').hasMatch(suffix)) {
        return true;
      }
    }
    return false;
  }

  static bool _mutatesIteratedTable(
    List<String> lines,
    int lineIndex,
    String line,
  ) {
    final Match? loop = cachedRegExp(
      r'^for\b.*\bin\s+(?:i?pairs)\s*\((.+)\)\s*do\s*$',
    ).firstMatch(line);
    if (loop == null) return false;

    final String iterated = loop.requiredGroup(1).trim();
    if (!_tableExpression.hasMatch(iterated)) return false;

    final Set<String> aliases = <String>{iterated};
    final Map<String, String> localAliases = <String, String>{};
    var scopeStart = 0;
    for (var index = lineIndex - 1; index >= 0; index--) {
      final String candidate = _strip(lines[index]).split('--').first.trim();
      if (cachedRegExp(r'^(?:local\s+)?function\b').hasMatch(candidate)) {
        scopeStart = index + 1;
        break;
      }
    }
    for (var index = scopeStart; index < lineIndex; index++) {
      final String candidate = _strip(lines[index]).split('--').first.trim();
      final Match? assignment = cachedRegExp(
        r'^(local\s+)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$',
      ).firstMatch(candidate);
      if (assignment == null) continue;
      final String name = assignment.requiredGroup(2);
      if (assignment.group(1) == null) {
        localAliases.remove(name);
      } else {
        localAliases[name] = assignment.requiredGroup(3);
      }
    }
    var addedAlias = true;
    while (addedAlias) {
      addedAlias = false;
      for (final MapEntry<String, String> alias in localAliases.entries) {
        if ((aliases.contains(alias.key) || aliases.contains(alias.value)) &&
            aliases.add(alias.key) | aliases.add(alias.value)) {
          addedAlias = true;
        }
      }
    }

    var depth = 1;
    for (var index = lineIndex + 1; index < lines.length; index++) {
      final String candidate = _strip(lines[index]).split('--').first.trim();
      if (aliases.any((String alias) => _mutatesTable(candidate, alias))) {
        return true;
      }
      depth += _blockDepthDelta(candidate);
      if (depth <= 0) return false;
    }
    return false;
  }

  static bool _mutatesTable(String line, String table) {
    final String escaped = RegExp.escape(table);
    final RegExp indexedAssignment = cachedRegExp(
      '(?:^|[^A-Za-z0-9_.])$escaped\\s*\\[[^\\]]+\\]\\s*=(?!=)',
    );
    final RegExp structuralCall = cachedRegExp(
      'table\\.(?:insert|remove|sort)\\s*\\(\\s*$escaped(?:\\s*[,\\)])',
    );
    final RegExp moveDestination = cachedRegExp(
      'table\\.move\\s*\\([^,]+,[^,]+,[^,]+,[^,]+,\\s*$escaped(?:\\s*[,\\)])',
    );
    return indexedAssignment.hasMatch(line) ||
        structuralCall.hasMatch(line) ||
        moveDestination.hasMatch(line);
  }

  static bool _declaresHotFunction(String line) {
    final Match? declaration = cachedRegExp(
      r'\bfunction\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\(',
    ).firstMatch(line);
    final Match? assignment = cachedRegExp(
      r'([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*=\s*function\s*\(',
    ).firstMatch(line);
    final String? qualifiedName = declaration?.group(1) ?? assignment?.group(1);
    if (qualifiedName == null) return false;
    final String name = qualifiedName
        .split(cachedRegExp(r'[.:]'))
        .last
        .toLowerCase();
    return name == 'update' || name == 'draw';
  }

  static final RegExp _tableExpression = cachedRegExp(
    r'^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$',
  );

  static int _blockDepthDelta(String line) {
    var delta = 0;
    if (cachedRegExp(r'\bfunction\b').hasMatch(line)) delta++;
    if (cachedRegExp(
      r'^(?:if\b.*\bthen|for\b.*\bdo|while\b.*\bdo|repeat\b|do\b)',
    ).hasMatch(line)) {
      delta++;
    }
    delta -= cachedRegExp(r'\bend\b').allMatches(line).length;
    if (cachedRegExp(r'^until\b').hasMatch(line)) delta--;
    return delta;
  }

  static final RegExp _luaLongBracketOpening = cachedRegExp(r'\[(=*)\[');
  static final RegExp _luaLongCommentOpening = cachedRegExp(r'^--\[(=*)\[');
  static List<String> _codeOutsideLuaLongBracketsAndComments(
    List<String> lines,
  ) {
    final List<String> result = <String>[];
    String? longBracketEnd;
    for (final String rawLine in lines) {
      final scanned = _withoutLuaLongBracketsAndComments(
        _strip(rawLine),
        longBracketEnd,
      );
      result.add(scanned.code);
      longBracketEnd = scanned.longBracketEnd;
    }
    return result;
  }

  static ({String code, String? longBracketEnd})
  _withoutLuaLongBracketsAndComments(String line, String? longBracketEnd) {
    final StringBuffer code = StringBuffer();
    var offset = 0;
    if (longBracketEnd != null) {
      final int close = line.indexOf(longBracketEnd);
      if (close < 0) {
        return (code: '', longBracketEnd: longBracketEnd);
      }
      offset = close + longBracketEnd.length;
      longBracketEnd = null;
    }

    while (offset < line.length) {
      final int comment = line.indexOf('--', offset);
      final RegExpMatch? opening = _luaLongBracketOpening.firstMatch(
        line.substring(offset),
      );
      final int openingOffset = opening == null ? -1 : offset + opening.start;
      if (comment >= 0 && (openingOffset < 0 || comment < openingOffset)) {
        code.write(line.substring(offset, comment));
        final RegExpMatch? commentOpening = _luaLongCommentOpening.firstMatch(
          line.substring(comment),
        );
        if (commentOpening == null) break;
        final String closing = ']${commentOpening.requiredGroup(1)}]';
        final int close = line.indexOf(closing, comment + commentOpening.end);
        if (close < 0) {
          return (code: code.toString(), longBracketEnd: closing);
        }
        offset = close + closing.length;
        continue;
      }
      if (opening == null) {
        code.write(line.substring(offset));
        break;
      }

      code.write(line.substring(offset, openingOffset));
      final String closing = ']${opening.requiredGroup(1)}]';
      final int close = line.indexOf(closing, offset + opening.end);
      if (close < 0) {
        return (code: code.toString(), longBracketEnd: closing);
      }
      offset = close + closing.length;
    }
    return (code: code.toString(), longBracketEnd: longBracketEnd);
  }

  static String _strip(String line) => line.replaceAll(
    cachedRegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''),
    '',
  );
}
