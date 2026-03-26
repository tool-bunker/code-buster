// Python diagnostics share indentation, import, exception, and call-context facts, making a coordinated pass both faster and more consistent.

import '../../core/models.dart';

/// Shared scan used by independently registered Python rules.
final class PythonRuleAnalysis {
  /// Emits findings for [ruleId] in source order.
  List<Finding> findings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      var sawCode = false;
      var importContinuationDepth = 0;
      var typeCheckingIndent = -1;
      var asyncIndent = -1;
      int? continuedStringQuote;
      String? tripleQuotedStringDelimiter;
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index];
        final bool startsInContinuedString = continuedStringQuote != null;
        String code;
        if (startsInContinuedString) {
          continuedStringQuote = _continuedStringQuoteAfter(
            raw,
            continuedStringQuote,
          );
          code = '';
        } else {
          final ({String code, String? delimiter}) scanned =
              _codeOutsideTripleQuotedStrings(raw, tripleQuotedStringDelimiter);
          tripleQuotedStringDelimiter = scanned.delimiter;
          continuedStringQuote = tripleQuotedStringDelimiter == null
              ? _continuedStringQuoteAfter(scanned.code, null)
              : null;
          code = _codeBeforeComment(scanned.code);
        }
        final String line = _strip(code).trim();
        final int indent = raw.length - raw.trimLeft().length;
        final bool inImportContinuation = importContinuationDepth > 0;
        final bool inTypeCheckingBlock =
            typeCheckingIndent >= 0 && indent > typeCheckingIndent;
        if (typeCheckingIndent >= 0 &&
            line.isNotEmpty &&
            indent <= typeCheckingIndent &&
            !line.startsWith('if TYPE_CHECKING:')) {
          typeCheckingIndent = -1;
        }
        if (line.startsWith('if TYPE_CHECKING:')) {
          typeCheckingIndent = indent;
        }
        if (line.startsWith('async def ')) asyncIndent = indent;
        if (asyncIndent >= 0 &&
            line.isNotEmpty &&
            indent <= asyncIndent &&
            !line.startsWith('async def ')) {
          asyncIndent = -1;
        }
        void add(String id, RuleSeverity severity, String message, {int? at}) {
          if (id != ruleId) return;
          result.add(
            _finding(id, severity, entry.key, at ?? index + 1, message),
          );
        }

        if (line.startsWith('import ') && line.contains(',')) {
          add(
            'py-multiple-imports',
            RuleSeverity.info,
            'multiple modules imported on one line',
          );
        }
        if (line.startsWith('from ') && line.endsWith(' import *')) {
          add('py-wildcard-import', RuleSeverity.warn, 'wildcard import used');
        }
        if ((line.startsWith('import ') || line.startsWith('from ')) &&
            indent == 0 &&
            sawCode &&
            !inTypeCheckingBlock) {
          add(
            'py-import-not-top',
            RuleSeverity.info,
            'import appears after executable code',
          );
        }
        final int suiteColon = line.lastIndexOf(':');
        final bool compoundHeader =
            suiteColon >= 0 &&
            RegExp(r'^(?:if|for|while|try|except|finally)\b').hasMatch(line) &&
            line.substring(suiteColon + 1).trim().isNotEmpty;
        if (compoundHeader || RegExp(r';\s*\S').hasMatch(line)) {
          add(
            'py-compound-statement',
            RuleSeverity.info,
            'compound statement on one line',
          );
        }
        if (RegExp(
          r'\(\s|\s[,;]|\s[)\]}]',
        ).hasMatch(_maskStrings(code.trim()))) {
          add(
            'py-extraneous-whitespace',
            RuleSeverity.info,
            'extraneous whitespace in expression',
          );
        }
        if (code.trimRight().endsWith(r'\')) {
          add(
            'py-backslash-continuation',
            RuleSeverity.info,
            'backslash line continuation used',
          );
        }
        final RegExpMatch? function = RegExp(
          r'^(?:async\s+)?def\s+([^\s(]+)',
        ).firstMatch(line);
        if (function != null &&
            !_httpRequestHandlerMethod.hasMatch(function.group(1)!) &&
            !_pythonTestLifecycleMethod.hasMatch(function.group(1)!) &&
            !_isComInterfaceMethod(lines, index, indent) &&
            (function.group(1)!.contains('-') ||
                RegExp(r'[A-Z]').hasMatch(function.group(1)!))) {
          add(
            'py-function-naming',
            RuleSeverity.info,
            'function name is not lower_snake_case',
          );
        }
        if (function != null &&
            RegExp(r'=\s*(?:\[\]|\{}|set\(|dict\(|list\()').hasMatch(line)) {
          add(
            'py-mutable-default',
            RuleSeverity.warn,
            'mutable default argument used',
          );
        }
        if (line == 'except:' || line.startsWith('except:')) {
          add(
            'py-bare-except',
            RuleSeverity.warn,
            'bare except catches all exceptions',
          );
        }
        if (line.startsWith('except Exception') ||
            line.startsWith('except BaseException')) {
          add('py-broad-except', RuleSeverity.info, 'broad exception handler');
        }
        if (function == null &&
            (RegExp(r'(?:^|[^\w.])(?:eval|exec)\s*\(').hasMatch(line) ||
                RegExp(r'\bbuiltins\.(?:eval|exec)\s*\(').hasMatch(line))) {
          add(
            'py-eval-exec',
            RuleSeverity.error,
            'dynamic code execution used',
          );
        }
        if ((line.contains('subprocess.') && line.contains('shell=True')) ||
            line.contains('os.system(') ||
            line.contains('popen(')) {
          add(
            'py-subprocess-shell',
            RuleSeverity.warn,
            'shell command execution needs review',
          );
        }
        if (line.startsWith('assert ') && !_isTestPath(entry.key)) {
          add(
            'py-assert-runtime',
            RuleSeverity.info,
            'assert used outside tests',
          );
        }
        if (RegExp(
              r'requests\.(?:get|post|put|patch|delete|request)\(',
            ).hasMatch(line) &&
            !RegExp(r'\btimeout\s*=').hasMatch(_continuedCall(lines, index))) {
          add(
            'py-requests-timeout',
            RuleSeverity.warn,
            'requests call has no timeout',
          );
        }
        if (line.contains('yaml.load(') &&
            !line.contains('SafeLoader') &&
            !line.contains('safe_load') &&
            !_usesSafeRuamelYaml(lines, index)) {
          add(
            'py-yaml-load',
            RuleSeverity.error,
            'yaml.load without SafeLoader',
          );
        }
        if (RegExp(
          r'\bpickle\.loads?\s*\(|\bfrom\s+pickle\s+import\b[^#]*\bloads?\b',
        ).hasMatch(line)) {
          add(
            'py-pickle',
            RuleSeverity.warn,
            'pickle usage needs trust-boundary review',
          );
        }
        if (_hasDynamicSqlStringExpression(code)) {
          add(
            'py-sql-string-build',
            RuleSeverity.warn,
            'SQL appears dynamically constructed',
          );
        }
        final RegExpMatch? secretAssignment = _hardcodedSecretAssignment
            .firstMatch(code);
        final RegExpMatch? hardcodedSecret =
            secretAssignment ?? _hardcodedSecretMapEntry.firstMatch(code);
        if (hardcodedSecret != null &&
            (secretAssignment == null ||
                !_repeatedFillerSecretAssignment.hasMatch(code)) &&
            !_emptyHardcodedSecret.hasMatch(code) &&
            !_isPlaceholderSecret(hardcodedSecret.group(0)!, entry.key)) {
          add(
            'py-hardcoded-secret',
            RuleSeverity.warn,
            'possible hardcoded secret',
          );
        }
        if (RegExp(
          r'''hashlib\.(?:md5|sha1)\(|\.new\(["'](?:md5|sha1)["']''',
          caseSensitive: false,
        ).hasMatch(raw)) {
          add('py-weak-hash', RuleSeverity.warn, 'weak hash algorithm used');
        }
        if (line.contains('tempfile.mktemp(')) {
          add(
            'py-tempfile-mktemp',
            RuleSeverity.warn,
            'tempfile.mktemp is race-prone',
          );
        }
        if (RegExp(
          r'\bdebug\s*=\s*true',
          caseSensitive: false,
        ).hasMatch(line)) {
          add(
            'py-debug-enabled',
            RuleSeverity.warn,
            'debug mode appears enabled',
          );
        }
        if (RegExp(r'(?:^|[^\w.])open\s*\(').hasMatch(line) &&
            !_expectsOpenFailure(lines, index)) {
          final String call = _continuedCall(lines, index);
          if (!call.contains('encoding=') &&
              !RegExp(
                r'''["'][rwa+x]*b[rwa+x]*["']''',
                caseSensitive: false,
              ).hasMatch(call)) {
            add(
              'py-open-no-encoding',
              RuleSeverity.info,
              'text file opened without explicit encoding',
            );
          }
        }
        if ((line.startsWith('except ') || line == 'except:') &&
            index + 1 < lines.length) {
          final String handlerOutput = _strip(lines[index + 1]).trim();
          if (handlerOutput.startsWith('print(') &&
              !_stderrPrintTarget.hasMatch(handlerOutput) &&
              !_exceptionHandlerTerminates(lines, index)) {
            add(
              'py-logging-exception',
              RuleSeverity.info,
              'exception handler prints instead of logging',
              at: index + 2,
            );
          }
        }
        if (asyncIndent >= 0 &&
            RegExp(
              r'\b(?:time\.sleep|requests\.(?:get|post)|subprocess\.run)\(',
            ).hasMatch(line)) {
          add(
            'py-async-blocking-call',
            RuleSeverity.warn,
            'blocking call inside async function',
          );
        }
        if (line.isNotEmpty &&
            !inImportContinuation &&
            !line.startsWith('#') &&
            !line.startsWith('import ') &&
            !line.startsWith('from ') &&
            !line.startsWith('"""') &&
            !line.startsWith("'''") &&
            !line.startsWith('__')) {
          sawCode = true;
        }
        final int bracketDelta = _bracketDelta(_maskStrings(raw));
        if (inImportContinuation) {
          importContinuationDepth += bracketDelta;
        } else if ((line.startsWith('import ') || line.startsWith('from ')) &&
            bracketDelta > 0) {
          importContinuationDepth = bracketDelta;
        }
      }
    }
    return result;
  }

  static Finding _finding(
    String id,
    RuleSeverity severity,
    String path,
    int line,
    String message,
  ) => Finding(
    code: id,
    severity: severity,
    path: path,
    line: line,
    endLine: line,
    message: message,
    confidence: 'medium',
    why: switch (id) {
      'py-requests-timeout' =>
        'HTTP calls without timeouts can hang indefinitely and exhaust workers.',
      _ =>
        'This scripting construct can weaken correctness, security, or runtime performance.',
    },
    suggestion: switch (id) {
      'py-requests-timeout' =>
        'Pass an explicit timeout, e.g. `timeout=10` or a connect/read tuple.',
      _ => 'Use the safer explicit pattern described by the rule.',
    },
  );
  static String _strip(String line) => line.replaceAll(_quotedString, '');

  static String _maskStrings(String line) => line.replaceAllMapped(
    _quotedString,
    (Match match) => 'x' * match.group(0)!.length,
  );
  static bool _exceptionHandlerTerminates(List<String> lines, int exceptIndex) {
    final int handlerIndent = _leadingIndent(lines[exceptIndex]);
    int? bodyIndent;
    for (var index = exceptIndex + 1; index < lines.length; index++) {
      final String raw = lines[index];
      final String line = raw.trim();
      if (line.isEmpty || line.startsWith('#')) continue;

      final int indent = _leadingIndent(raw);
      if (indent <= handlerIndent) break;
      bodyIndent ??= indent;
      if (indent != bodyIndent) continue;
      if (RegExp(r'^(?:return\b|raise\b|(?:sys\.)?exit\s*\()').hasMatch(line)) {
        return true;
      }
    }
    return false;
  }

  static int _leadingIndent(String line) {
    final RegExpMatch? match = RegExp(r'^[ \t]*').firstMatch(line);
    return match?.group(0)!.length ?? 0;
  }

  static int _bracketDelta(String line) {
    var depth = 0;
    for (final int character in line.codeUnits) {
      if (character == 40 || character == 91 || character == 123) depth++;
      if (character == 41 || character == 93 || character == 125) depth--;
    }
    return depth;
  }

  static String _continuedCall(List<String> lines, int start) {
    final StringBuffer call = StringBuffer();
    var depth = 0;
    for (var index = start; index < lines.length; index++) {
      if (call.isNotEmpty) call.write('\n');
      call.write(lines[index]);
      depth += _bracketDelta(_maskStrings(lines[index]));
      if (depth <= 0) break;
    }
    return call.toString();
  }

  static bool _usesSafeRuamelYaml(List<String> lines, int index) {
    for (var lineIndex = index - 1; lineIndex >= 0; lineIndex--) {
      final String candidate = _codeBeforeComment(lines[lineIndex]).trim();
      if (!RegExp(r'\byaml\s*=\s*YAML\s*\(').hasMatch(candidate)) continue;
      return RegExp(
        r'''\btyp\s*=\s*["']safe["']''',
        caseSensitive: false,
      ).hasMatch(_continuedCall(lines, lineIndex));
    }
    return false;
  }

  static bool _hasDynamicSqlStringExpression(String code) {
    for (final RegExpMatch literalMatch in _quotedString.allMatches(code)) {
      final String literal = literalMatch.group(0)!;
      if (!_sqlStatement.hasMatch(literal)) continue;

      final String before = code.substring(0, literalMatch.start);
      final String after = code.substring(literalMatch.end);
      final bool interpolatedFString =
          _pythonFStringPrefix.hasMatch(before) &&
          _pythonFStringField.hasMatch(literal);
      if (interpolatedFString ||
          _dynamicSqlLiteralSuffix.hasMatch(after) ||
          _dynamicSqlLiteralPrefix.hasMatch(before)) {
        return true;
      }
    }
    return false;
  }

  static final RegExp _pythonFStringPrefix = RegExp(
    r'(?:^|[^\w])(?:f[r]?|r[f])$',
    caseSensitive: false,
  );
  static final RegExp _pythonFStringField = RegExp(
    r'(?<!\{)\{[^{}\n]+\}(?!\})',
  );
  static final RegExp _dynamicSqlLiteralSuffix = RegExp(
    r'''^\s*(?:\.format\s*\(|%\s*(?=[A-Za-z_(\[])|\+\s*(?!["']))''',
  );
  static final RegExp _dynamicSqlLiteralPrefix = RegExp(
    r'''(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\([^)]*\))?|\)|\])\s*\+\s*$''',
  );

  static bool _isComInterfaceMethod(
    List<String> lines,
    int methodIndex,
    int methodIndent,
  ) {
    for (var index = methodIndex - 1; index >= 0; index--) {
      final String candidate = lines[index].trim();
      if (candidate.isEmpty || candidate.startsWith('#')) continue;
      final int candidateIndent =
          lines[index].length - lines[index].trimLeft().length;
      if (candidateIndent >= methodIndent) continue;
      if (!RegExp(
        r'^class\s+\w+\s*\([^)]*\bcomtypes\.COMObject\b[^)]*\)\s*:',
      ).hasMatch(candidate)) {
        return false;
      }
      return lines
          .skip(index + 1)
          .take(methodIndex - index - 1)
          .any((String line) => line.trimLeft().startsWith('_com_interfaces_'));
    }
    return false;
  }

  static bool _isTestPath(String path) {
    final String normalized = path.replaceAll(r'\', '/').toLowerCase();
    final String name = normalized.substring(normalized.lastIndexOf('/') + 1);
    return _pythonTestDirectory.hasMatch(normalized) ||
        name.startsWith('test_') ||
        name.endsWith('_test.py');
  }

  static final RegExp _pythonTestDirectory = RegExp(
    r'(?:^|/)(?:test|tests|__tests__)(?:/|$)',
  );

  static String _codeBeforeComment(String line) {
    int? quote;
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final int character = line.codeUnitAt(index);
      if (quote != null) {
        if (escaped) {
          escaped = false;
        } else if (character == 92) {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
      } else if (character == 34 || character == 39) {
        quote = character;
      } else if (character == 35) {
        return line.substring(0, index);
      }
    }
    return line;
  }

  static int? _continuedStringQuoteAfter(String line, int? quote) {
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final int character = line.codeUnitAt(index);
      if (quote != null) {
        if (escaped) {
          escaped = false;
        } else if (character == 92) {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
      } else if (character == 34 || character == 39) {
        quote = character;
      } else if (character == 35) {
        break;
      }
    }
    return quote != null && line.trimRight().endsWith(r'\') ? quote : null;
  }

  static ({String code, String? delimiter}) _codeOutsideTripleQuotedStrings(
    String line,
    String? delimiter,
  ) {
    final StringBuffer code = StringBuffer();
    var cursor = 0;
    while (cursor < line.length) {
      if (delimiter != null) {
        var closing = line.indexOf(delimiter, cursor);
        while (closing >= 0 && _isEscaped(line, closing)) {
          closing = line.indexOf(delimiter, closing + delimiter.length);
        }
        if (closing < 0) {
          return (code: code.toString(), delimiter: delimiter);
        }
        cursor = closing + delimiter.length;
        delimiter = null;
        continue;
      }

      if (line.codeUnitAt(cursor) == 35) break;
      final Match? stringStart = _pythonStringStart.matchAsPrefix(line, cursor);
      final bool atTokenBoundary =
          cursor == 0 || !RegExp(r'[A-Za-z0-9_]').hasMatch(line[cursor - 1]);
      if (stringStart == null || !atTokenBoundary) {
        code.writeCharCode(line.codeUnitAt(cursor));
        cursor++;
        continue;
      }

      final String quote = stringStart.group(1)!;
      if (quote.length == 3) {
        delimiter = quote;
        cursor = stringStart.end;
        continue;
      }

      final int literalStart = cursor;
      cursor = stringStart.end;
      var escaped = false;
      while (cursor < line.length) {
        final int character = line.codeUnitAt(cursor++);
        if (escaped) {
          escaped = false;
        } else if (character == 92) {
          escaped = true;
        } else if (character == quote.codeUnitAt(0)) {
          break;
        }
      }
      code.write(line.substring(literalStart, cursor));
    }
    return (code: code.toString(), delimiter: delimiter);
  }

  static bool _isEscaped(String source, int offset) {
    var backslashes = 0;
    for (
      var index = offset - 1;
      index >= 0 && source.codeUnitAt(index) == 92;
      index--
    ) {
      backslashes++;
    }
    return backslashes.isOdd;
  }

  static final RegExp _httpRequestHandlerMethod = RegExp(
    r'^do_(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$',
  );
  static final RegExp _pythonTestLifecycleMethod = RegExp(
    r'^(?:setUp|tearDown)(?:Class|Module)?$',
  );

  static final RegExp _pythonStringStart = RegExp(
    "[rRuUbBfF]{0,2}(\"{3}|'{3}|\"|')",
  );

  static bool _expectsOpenFailure(List<String> lines, int index) {
    if (index == 0) return false;
    return RegExp(
      r'^(?:with\s+)?(?:(?:self\.)?assertRaises|pytest\.raises)\(\s*(?:FileNotFoundError|PermissionError|IsADirectoryError)\s*\)\s*:\s*$',
    ).hasMatch(lines[index - 1].trim());
  }

  static final RegExp _stderrPrintTarget = RegExp(
    r'\bfile\s*=\s*sys\.stderr\b',
  );

  static final RegExp _sqlStatement = RegExp(
    r'\b(?:select\b[^\n]*\bfrom\b|insert\s+into\b|update\s+[A-Za-z_][\w.]*\s+set\b|delete\s+from\b)',
    caseSensitive: false,
  );

  static final RegExp _quotedString = RegExp(
    r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''',
  );
  static const String _quotedLiteral =
      r'''[rRuUbBfF]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')''';
  static final RegExp _hardcodedSecretAssignment = RegExp(
    '''\\b(?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)\\s*=\\s*$_quotedLiteral\\s*(?:[,}\\])]|\$)''',
    caseSensitive: false,
  );
  static final RegExp _hardcodedSecretMapEntry = RegExp(
    '''["'](?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)["']\\s*:\\s*$_quotedLiteral\\s*(?:[,}\\])]|\$)''',
    caseSensitive: false,
  );
  static final RegExp _emptyHardcodedSecret = RegExp(
    r'''(?:(?:\b(?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)\s*=)|(?:["'](?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)["']\s*:))\s*[rRuUbBfF]{0,2}(?:"\s*"|'\s*')''',
    caseSensitive: false,
  );
  static bool _isPlaceholderSecret(String match, String path) {
    final List<RegExpMatch> literals = _secretStringLiteral
        .allMatches(match)
        .toList(growable: false);
    if (literals.isEmpty) return false;
    final RegExpMatch literal = literals.last;
    final String value = (literal.group(1) ?? literal.group(2) ?? '').trim();
    if (_documentationSecretPlaceholder.hasMatch(value)) return true;

    return _isTestPath(path) && _testSecretPlaceholder.hasMatch(value);
  }

  static final RegExp _secretStringLiteral = RegExp(
    r'''[rRuUbBfF]{0,2}(?:"([^"]*)"|'([^']*)')''',
  );
  static final RegExp _documentationSecretPlaceholder = RegExp(
    r'(?:^|[-_])your(?:[-_])(?:[a-z0-9]+[-_])*(?:key|token|secret|password|credential)(?:$|[-_])|(?:^|[-_])replace[-_]?me(?:$|[-_])',
    caseSensitive: false,
  );
  static final RegExp _testSecretPlaceholder = RegExp(
    r'^(?:test|test[-_](?:api[-_]?key|key|token|secret|password)|fc[-_]test)$',
    caseSensitive: false,
  );

  static final RegExp _repeatedFillerSecretAssignment = RegExp(
    r'''\b(?:password|passwd|secret|api_key|apikey|token)\w*\s*=\s*[rRuUbBfF]{0,2}["'][^"'\\]["']\s*\*\s*\(?\s*\d+''',
    caseSensitive: false,
  );
}
