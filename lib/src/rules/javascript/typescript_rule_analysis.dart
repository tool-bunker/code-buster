// TypeScript-only findings share type-shaped syntax and module context, so one analysis pass supplies their evidence.

import '../../core/models.dart';

/// Shared scan used by independently registered JavaScript/TypeScript rules.
final class TypeScriptRuleAnalysis {
  /// Emits findings for [ruleId] in source order.
  List<Finding> findings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      final String uncommentedSource = _withoutComments(entry.value);
      final List<String> uncommentedLines = uncommentedSource.split('\n');
      final List<String> codeLines = _withoutTemplateLiterals(
        uncommentedSource,
      ).split('\n');
      final List<String> sinkCodeLines = _withoutStringLiteralText(
        uncommentedSource,
      ).split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index];
        final String line = _strip(codeLines[index]).trim();
        final String lower = raw.toLowerCase();
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
              why: id == 'ts-console'
                  ? 'Console logging in app/library code can leak data and create noisy production output.'
                  : 'This scripting construct can weaken correctness, security, or runtime performance.',
              suggestion: id == 'ts-console'
                  ? 'Use a structured logger or remove debug logging before release.'
                  : 'Use the safer explicit pattern described by the rule.',
            ),
          );
        }

        if (line.contains(': any') ||
            line.contains('<any>') ||
            line.contains(' as any')) {
          add('ts-any', RuleSeverity.info, 'explicit any type used');
        }
        if (RegExp(r'!\s*(?:\.|\)|;|,|\])').hasMatch(line) &&
            !line.startsWith('if ')) {
          add(
            'ts-non-null-assertion',
            RuleSeverity.info,
            'non-null assertion used',
          );
        }
        if (line.contains('console.log(') || line.contains('console.debug(')) {
          add('ts-console', RuleSeverity.info, 'console logging left in code');
        }
        if (line == 'debugger;') {
          add(
            'ts-debugger',
            RuleSeverity.warn,
            'debugger statement left in code',
          );
        }
        if ((_directEvalCall.hasMatch(line) ||
                    _globalEvalCall.hasMatch(line)) &&
                !_evalFunctionDeclaration.hasMatch(line) &&
                !_evalMethodDeclaration.hasMatch(line) ||
            RegExp(r'\bnew\s+Function\s*\(').hasMatch(line)) {
          add(
            'ts-eval',
            RuleSeverity.error,
            'dynamic JavaScript execution used',
          );
        }
        if (_hasUnsafeInnerHtmlSink(uncommentedLines, sinkCodeLines, index)) {
          add(
            'ts-inner-html',
            RuleSeverity.warn,
            'raw HTML injection sink used',
          );
        }
        final bool startsPromiseCall = _startsPromiseCall.hasMatch(line);
        final String continuedExpression = _continuedExpression(
          codeLines,
          index,
        );
        if (startsPromiseCall &&
            !_functionBindCall.hasMatch(line) &&
            !_isInsideAwaitedWrapper(codeLines, index) &&
            !_isImplicitArrowReturn(codeLines, index) &&
            !RegExp(
              r'\b(?:await|return|void)\b|\.(?:then|catch|subscribe)\s*\(',
            ).hasMatch(continuedExpression)) {
          add(
            'ts-floating-promise',
            RuleSeverity.warn,
            'promise-returning call is not awaited or returned',
          );
        }
        if (line.startsWith('await ') && _isInsideLoop(codeLines, index)) {
          add('ts-await-in-loop', RuleSeverity.info, 'await inside loop');
        }
        final RegExpMatch? secretAssignment = _hardcodedSecretAssignment(
          uncommentedLines[index],
          codeLines[index],
        );
        if (secretAssignment != null &&
            _secretIdentifier.hasMatch(secretAssignment.group(1)!) &&
            secretAssignment.group(2)!.trim().isNotEmpty &&
            !_isExplicitEmptySentinel(
              secretAssignment.group(1)!,
              secretAssignment.group(2)!,
            ) &&
            !_isPlaceholderSecret(
              secretAssignment.group(1)!,
              secretAssignment.group(2)!,
            ) &&
            !_isEnumMember(codeLines, index, secretAssignment.start + 1) &&
            !lower.contains('process.env') &&
            !lower.contains('import.meta.env')) {
          add(
            'ts-hardcoded-secret',
            RuleSeverity.warn,
            'possible hardcoded secret',
          );
        }
        if (line.contains('JSON.parse(') &&
            !_embeddedJsonElementParse.hasMatch(line) &&
            !_jsonRoundTripParse.hasMatch(line) &&
            !_isParseOfImmediatelyStringifiedValue(codeLines, index) &&
            !_isInsideHandledTry(codeLines, index) &&
            !RegExp(
              r'\b(?:safe|schema|zod|validate)\b',
              caseSensitive: false,
            ).hasMatch(line)) {
          add(
            'ts-json-parse-unsafe',
            RuleSeverity.info,
            'JSON.parse without obvious validation or handling',
          );
        }
        if (line.contains('localStorage.') && line.contains('JSON.parse(')) {
          add(
            'ts-localstorage-json',
            RuleSeverity.info,
            'localStorage JSON parsed directly',
          );
        }
      }
    }
    return result;
  }

  static RegExpMatch? _hardcodedSecretAssignment(
    String uncommentedLine,
    String codeLine,
  ) {
    final RegExpMatch? quoted = _literalAssignment.firstMatch(codeLine);
    if (quoted != null) return quoted;

    final RegExpMatch? template = _templateLiteralAssignment.firstMatch(
      uncommentedLine,
    );
    if (template == null || _hasTemplateInterpolation(template.group(2)!)) {
      return null;
    }
    final RegExpMatch? masked = _maskedTemplateAssignment.firstMatch(codeLine);
    return masked?.group(1) == template.group(1) ? template : null;
  }

  static bool _hasTemplateInterpolation(String literal) {
    var escaped = false;
    for (var index = 0; index + 1 < literal.length; index++) {
      final String character = literal[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character == r'\') {
        escaped = true;
        continue;
      }
      if (character == r'$' && literal[index + 1] == '{') return true;
    }
    return false;
  }

  static bool _isImplicitArrowReturn(List<String> lines, int index) {
    for (var lineIndex = index - 1; lineIndex >= 0; lineIndex--) {
      final String previous = _strip(lines[lineIndex]).trim();
      if (previous.isEmpty) continue;
      return previous.endsWith('=>');
    }
    return false;
  }

  static bool _isInsideAwaitedWrapper(List<String> lines, int index) {
    for (var lineIndex = index - 1; lineIndex >= 0; lineIndex--) {
      final String previous = _strip(lines[lineIndex]).trim();
      if (previous.isEmpty) continue;
      if (previous.endsWith(';') || previous == '}') return false;
      if (RegExp(r'\bawait\b.*(?:\(|\[|\{)\s*$').hasMatch(previous)) {
        return true;
      }
    }
    return false;
  }

  static bool _isEnumMember(
    List<String> lines,
    int index,
    int assignmentOffset,
  ) {
    final List<bool> openBlocks = <bool>[];
    for (var lineIndex = 0; lineIndex <= index; lineIndex++) {
      final String code = _strip(lines[lineIndex]);
      final int limit = lineIndex == index ? assignmentOffset : code.length;
      for (var offset = 0; offset < limit; offset++) {
        final String character = code[offset];
        if (character == '}') {
          if (openBlocks.isNotEmpty) openBlocks.removeLast();
          continue;
        }
        if (character != '{') continue;

        var prefix = code.substring(0, offset).trimRight();
        if (prefix.isEmpty && lineIndex > 0) {
          prefix = _strip(lines[lineIndex - 1]).trimRight();
        }
        openBlocks.add(
          RegExp(r'(?:^|\s)(?:const\s+)?enum\s+[\w$]+\s*$').hasMatch(prefix),
        );
      }
    }
    return openBlocks.any((bool isEnum) => isEnum);
  }

  static String _continuedExpression(List<String> lines, int start) {
    final StringBuffer expression = StringBuffer();
    var depth = 0;
    for (var index = start; index < lines.length; index++) {
      final String code = _strip(lines[index]);
      if (expression.isNotEmpty) expression.write('\n');
      expression.write(code);
      for (final int character in code.codeUnits) {
        if (character == 40 || character == 91 || character == 123) depth++;
        if (character == 41 || character == 93 || character == 125) depth--;
      }
      if (depth > 0) continue;
      if (code.trimRight().endsWith(';')) break;

      final String? next = lines
          .skip(index + 1)
          .map(_strip)
          .map((String value) => value.trim())
          .where((String value) => value.isNotEmpty)
          .firstOrNull;
      if (next == null || !next.startsWith('.')) break;
    }
    return expression.toString();
  }

  static bool _isInsideLoop(List<String> lines, int index) {
    final List<({bool function, bool loop})> openBlocks =
        <({bool function, bool loop})>[];
    for (var lineIndex = 0; lineIndex < index; lineIndex++) {
      final String code = _strip(lines[lineIndex]);
      for (var offset = 0; offset < code.length; offset++) {
        final String character = code[offset];
        if (character == '}') {
          if (openBlocks.isNotEmpty) openBlocks.removeLast();
          continue;
        }
        if (character != '{') continue;

        var prefix = code.substring(0, offset).trimRight();
        if (prefix.isEmpty && lineIndex > 0) {
          prefix = _strip(lines[lineIndex - 1]).trimRight();
        }
        openBlocks.add((
          function: RegExp(
            r'(?:=>|\bfunction(?:\s*\*)?(?:\s+[\w$]+)?\s*\([^)]*\))\s*$',
          ).hasMatch(prefix),
          loop:
              RegExp(
                r'\b(?:for\s*(?:await\s*)?|while\s*)\(',
              ).hasMatch(prefix) ||
              RegExp(r'\bdo\s*$').hasMatch(prefix),
        ));
      }
    }

    for (final ({bool function, bool loop}) block in openBlocks.reversed) {
      if (block.function) return false;
      if (block.loop) return true;
    }
    return false;
  }

  static bool _isInsideHandledTry(List<String> lines, int index) {
    final List<String> structuralLines = lines
        .map(_strip)
        .toList(growable: false);
    final int offsetInLine = structuralLines[index].indexOf('JSON.parse(');
    if (offsetInLine < 0) return false;

    var parseOffset = offsetInLine;
    for (var lineIndex = 0; lineIndex < index; lineIndex++) {
      parseOffset += structuralLines[lineIndex].length + 1;
    }
    final String source = _withoutComments(structuralLines.join('\n'));
    final List<int> openBlocks = <int>[];
    for (var offset = 0; offset < parseOffset; offset++) {
      if (source[offset] == '{') {
        openBlocks.add(offset);
      } else if (source[offset] == '}' && openBlocks.isNotEmpty) {
        openBlocks.removeLast();
      }
    }

    for (final int open in openBlocks.reversed) {
      if (!RegExp(r'\btry\s*$').hasMatch(source.substring(0, open))) continue;
      final int close = _matchingBlockClose(source, open);
      if (close < 0) continue;
      if (RegExp(
        r'^(?:(?:\s|//[^\n]*(?:\n|$)|/\*[\s\S]*?\*/))*catch\b',
      ).hasMatch(source.substring(close + 1))) {
        return true;
      }
    }
    return false;
  }

  static int _matchingBlockClose(String source, int open) {
    var depth = 0;
    for (var offset = open; offset < source.length; offset++) {
      if (source[offset] == '{') {
        depth++;
      } else if (source[offset] == '}') {
        depth--;
        if (depth == 0) return offset;
      }
    }
    return -1;
  }

  static String _withoutComments(String source) {
    final StringBuffer result = StringBuffer();
    String? quote;
    var escaped = false;
    var inLineComment = false;
    var inBlockComment = false;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      final String next = index + 1 < source.length ? source[index + 1] : '';
      if (inLineComment) {
        if (character == '\n') {
          inLineComment = false;
          result.write(character);
        } else {
          result.write(' ');
        }
        continue;
      }
      if (inBlockComment) {
        if (character == '*' && next == '/') {
          inBlockComment = false;
          result.write('  ');
          index++;
        } else {
          result.write(character == '\n' ? '\n' : ' ');
        }
        continue;
      }
      if (quote != null) {
        result.write(character);
        if (escaped) {
          escaped = false;
        } else if (character == r'\') {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'" || character == '`') {
        quote = character;
        result.write(character);
      } else if (character == '/' && next == '/') {
        inLineComment = true;
        result.write('  ');
        index++;
      } else if (character == '/' && next == '*') {
        inBlockComment = true;
        result.write('  ');
        index++;
      } else {
        result.write(character);
      }
    }
    return result.toString();
  }

  static String _withoutTemplateLiterals(String source) {
    final StringBuffer result = StringBuffer();
    var inTemplate = false;
    var escaped = false;
    for (final int character in source.codeUnits) {
      if (!inTemplate) {
        if (character == 0x60) {
          inTemplate = true;
          result.write(' ');
        } else {
          result.writeCharCode(character);
        }
        continue;
      }
      if (character == 0x0A) {
        result.writeCharCode(character);
        escaped = false;
      } else {
        result.write(' ');
        if (escaped) {
          escaped = false;
        } else if (character == 0x5C) {
          escaped = true;
        } else if (character == 0x60) {
          inTemplate = false;
        }
      }
    }
    return result.toString();
  }

  static String _withoutStringLiteralText(String source) {
    final StringBuffer result = StringBuffer();
    final List<int> templateReturnDepths = <int>[];
    var mode = 0;
    var interpolationDepth = 0;
    var escaped = false;
    for (var index = 0; index < source.length; index++) {
      final int character = source.codeUnitAt(index);
      final int next = index + 1 < source.length
          ? source.codeUnitAt(index + 1)
          : -1;
      if (mode == 1 || mode == 2) {
        if (character == 0x0A) {
          result.writeCharCode(character);
          escaped = false;
        } else {
          result.write(' ');
          if (escaped) {
            escaped = false;
          } else if (character == 0x5C) {
            escaped = true;
          } else if ((mode == 1 && character == 0x27) ||
              (mode == 2 && character == 0x22)) {
            mode = 0;
          }
        }
        continue;
      }
      if (mode == 3) {
        if (character == 0x0A) {
          result.writeCharCode(character);
          escaped = false;
        } else if (!escaped && character == 0x24 && next == 0x7B) {
          result.write('  ');
          index++;
          mode = 0;
          interpolationDepth = 1;
        } else {
          result.write(' ');
          if (escaped) {
            escaped = false;
          } else if (character == 0x5C) {
            escaped = true;
          } else if (character == 0x60) {
            mode = 0;
            interpolationDepth = templateReturnDepths.removeLast();
          }
        }
        continue;
      }

      if (character == 0x27 || character == 0x22) {
        mode = character == 0x27 ? 1 : 2;
        result.write(' ');
      } else if (character == 0x60) {
        templateReturnDepths.add(interpolationDepth);
        mode = 3;
        result.write(' ');
      } else if (interpolationDepth > 0 && character == 0x7B) {
        interpolationDepth++;
        result.writeCharCode(character);
      } else if (interpolationDepth > 0 && character == 0x7D) {
        interpolationDepth--;
        if (interpolationDepth == 0) {
          mode = 3;
          result.write(' ');
        } else {
          result.writeCharCode(character);
        }
      } else {
        result.writeCharCode(character);
      }
    }
    return result.toString();
  }

  static String _strip(String line) => line.replaceAll(
    RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''),
    '',
  );

  static final RegExp _embeddedJsonElementParse = RegExp(
    r'JSON\.parse\(\s*document\.(?:querySelector|getElementById)\([^)]*\)\.(?:innerText|textContent)\s*\)',
  );
  static final RegExp _jsonRoundTripParse = RegExp(
    r'JSON\.parse\s*\(\s*JSON\.stringify\s*\(',
  );
  static bool _isParseOfImmediatelyStringifiedValue(
    List<String> lines,
    int index,
  ) {
    final RegExpMatch? parse = RegExp(
      r'\bJSON\.parse\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\)',
    ).firstMatch(lines[index]);
    if (parse == null) return false;

    for (var previous = index - 1; previous >= 0; previous--) {
      final String candidate = lines[previous].trim();
      if (candidate.isEmpty) continue;
      final String target = RegExp.escape(parse.group(1)!);
      return RegExp(
        '(?:^|[;{])\\s*$target\\s*=\\s*JSON\\.stringify\\s*\\(',
      ).hasMatch(candidate);
    }
    return false;
  }

  static final RegExp _startsPromiseCall = RegExp(
    r'^(?:fetch\s*\(|axios(?:\.[A-Za-z_$][\w$]*)*\s*\()',
  );
  static final RegExp _functionBindCall = RegExp(r'\.bind\s*\(');
  static final RegExp _innerHtmlAssignment = RegExp(
    r'\binnerHTML\s*(?:\?\?=|&&=|\|\|=|\*\*=|>>>=|<<=|>>=|[+\-*/%&|^]=|=(?!=|>))',
  );
  static final RegExp _innerHtmlUpdate = RegExp(
    r'(?:\+\+|--)\s*[\w$.[\]]*\.innerHTML\b|\binnerHTML\s*(?:\+\+|--)',
  );
  static bool _hasUnsafeInnerHtmlSink(
    List<String> rawLines,
    List<String> codeLines,
    int index,
  ) {
    final String codeLine = codeLines[index];
    if (codeLine.contains('dangerouslySetInnerHTML')) return true;
    if (_innerHtmlUpdate.hasMatch(codeLine)) return true;
    final RegExpMatch? assignment = _innerHtmlAssignment.firstMatch(codeLine);
    if (assignment == null) return false;

    final String rightHandSide = _innerHtmlRightHandSide(
      rawLines,
      index,
      assignment.end,
    );
    return !_isStaticInnerHtmlExpression(rightHandSide);
  }

  static String _innerHtmlRightHandSide(
    List<String> lines,
    int assignmentLine,
    int assignmentEnd,
  ) {
    final StringBuffer result = StringBuffer();
    String? quote;
    var escaped = false;
    var parentheses = 0;
    var brackets = 0;
    var braces = 0;
    var ternaries = 0;

    for (
      var lineIndex = assignmentLine;
      lineIndex < lines.length;
      lineIndex++
    ) {
      final String line = lines[lineIndex];
      final int start = lineIndex == assignmentLine ? assignmentEnd : 0;
      for (var offset = start; offset < line.length; offset++) {
        final String character = line[offset];
        if (quote != null) {
          result.write(character);
          if (escaped) {
            escaped = false;
          } else if (character == r'\') {
            escaped = true;
          } else if (character == quote) {
            quote = null;
          }
          continue;
        }
        if (character == '"' || character == "'" || character == '`') {
          quote = character;
        } else if (character == '(') {
          parentheses++;
        } else if (character == ')') {
          parentheses--;
        } else if (character == '[') {
          brackets++;
        } else if (character == ']') {
          brackets--;
        } else if (character == '{') {
          braces++;
        } else if (character == '}') {
          braces--;
        } else if (parentheses == 0 && brackets == 0 && braces == 0) {
          if (character == ';') return result.toString();
          if (character == '?' &&
              (offset + 1 >= line.length ||
                  (line[offset + 1] != '?' && line[offset + 1] != '.'))) {
            ternaries++;
          } else if (character == ':' && ternaries > 0) {
            ternaries--;
          }
        }
        result.write(character);
      }

      final String collected = result.toString().trimRight();
      if (quote == null &&
          parentheses == 0 &&
          brackets == 0 &&
          braces == 0 &&
          ternaries == 0 &&
          collected.isNotEmpty &&
          !RegExp(r'(?:\+|&&|\|\||\?\?|[?:])\s*$').hasMatch(collected)) {
        return collected;
      }
      result.writeln();
    }
    return result.toString();
  }

  static bool _isStaticInnerHtmlExpression(String source) {
    var expression = source.trim();
    while (_hasWrappingParentheses(expression)) {
      expression = expression.substring(1, expression.length - 1).trim();
    }
    if (expression.isEmpty) return false;
    if (_isStaticStringLiteral(expression) ||
        RegExp(
          r'^(?:true|false|null|-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$',
        ).hasMatch(expression)) {
      return true;
    }
    if (RegExp(
      r'''^[A-Za-z_$][\w$.[\]]*\s*\?\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*:\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')$''',
    ).hasMatch(expression)) {
      return true;
    }

    final List<int> operators = _topLevelStaticOperators(expression);
    final int question = operators.indexWhere(
      (int offset) => expression[offset] == '?',
    );
    if (question >= 0) {
      var nested = 0;
      for (final int offset in operators.where(
        (int value) => value > question,
      )) {
        final String operator = expression[offset];
        if (operator == '?') {
          nested++;
        } else if (operator == ':') {
          if (nested > 0) {
            nested--;
            continue;
          }
          return expression.substring(0, question).trim().isNotEmpty &&
              _isStaticInnerHtmlExpression(
                expression.substring(question + 1, offset),
              ) &&
              _isStaticInnerHtmlExpression(expression.substring(offset + 1));
        }
      }
      return false;
    }

    final List<int> pluses = operators
        .where((int offset) => expression[offset] == '+')
        .toList(growable: false);
    if (pluses.isEmpty) return false;
    var start = 0;
    for (final int plus in pluses) {
      if (!_isStaticInnerHtmlExpression(expression.substring(start, plus))) {
        return false;
      }
      start = plus + 1;
    }
    return _isStaticInnerHtmlExpression(expression.substring(start));
  }

  static List<int> _topLevelStaticOperators(String source) {
    final List<int> result = <int>[];
    String? quote;
    var escaped = false;
    var depth = 0;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      if (quote != null) {
        if (escaped) {
          escaped = false;
        } else if (character == r'\') {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'" || character == '`') {
        quote = character;
      } else if (character == '(' || character == '[' || character == '{') {
        depth++;
      } else if (character == ')' || character == ']' || character == '}') {
        depth--;
      } else if (depth == 0 &&
          (character == '+' || character == ':' || character == '?')) {
        if (character != '?' ||
            (index + 1 >= source.length ||
                (source[index + 1] != '?' && source[index + 1] != '.'))) {
          result.add(index);
        }
      }
    }
    return result;
  }

  static bool _hasWrappingParentheses(String source) {
    if (source.length < 2 ||
        source[0] != '(' ||
        source[source.length - 1] != ')') {
      return false;
    }
    String? quote;
    var escaped = false;
    var depth = 0;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      if (quote != null) {
        if (escaped) {
          escaped = false;
        } else if (character == r'\') {
          escaped = true;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'" || character == '`') {
        quote = character;
      } else if (character == '(') {
        depth++;
      } else if (character == ')' && --depth == 0) {
        return index == source.length - 1;
      }
    }
    return false;
  }

  static bool _isStaticStringLiteral(String source) {
    final String expression = source.trim();
    if (expression.length < 2) return false;
    final String quote = expression[0];
    if (quote != '"' && quote != "'" && quote != '`') return false;

    var escaped = false;
    for (var index = 1; index < expression.length; index++) {
      final String character = expression[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character == r'\') {
        escaped = true;
        continue;
      }
      if (quote == '`' &&
          character == r'$' &&
          index + 1 < expression.length &&
          expression[index + 1] == '{') {
        return false;
      }
      if (character == quote) return index == expression.length - 1;
    }
    return false;
  }
}

final RegExp _directEvalCall = RegExp(r'(?:^|[^\w$?.])eval\s*\(');
final RegExp _globalEvalCall = RegExp(
  r'\b(?:globalThis|window)\s*\.\s*eval\s*\(',
);
final RegExp _evalFunctionDeclaration = RegExp(r'\bfunction\s*\*?\s+eval\s*\(');
final RegExp _evalMethodDeclaration = RegExp(
  r'^(?:(?:public|private|protected|static|abstract|async|override)\s+)*eval\s*\([^)]*\)\s*(?::[^{]+)?\{',
);

final RegExp _literalAssignment = RegExp(
  r'''(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s*["']([^"']*)["'](?=\s*(?:[;,]|$))''',
);
final RegExp _templateLiteralAssignment = RegExp(
  r'''(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s*`((?:\\.|[^`])*)`(?=\s*(?:[;,]|$))''',
);
final RegExp _maskedTemplateAssignment = RegExp(
  r'''(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s+(?=[;,]|$)''',
);
final RegExp _secretIdentifier = RegExp(
  r'(?:^|_)(?:token|secret|password|passwd|api_?key|nonce|salt)$|(?:Token|Secret|Password|Passwd|ApiKey|Nonce|Salt)$',
);

final RegExp _emptySentinelLiteral = RegExp(
  r'^_?empty_?$',
  caseSensitive: false,
);

bool _isPlaceholderSecret(String identifier, String literal) {
  final String normalized = literal
      .replaceAll(RegExp(r'[^A-Za-z0-9]'), '')
      .toLowerCase();
  return const <String>{
        'test',
        'example',
        'placeholder',
        'changeme',
      }.contains(normalized) ||
      RegExp(
        r'^(?:(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)|(?:asdf){2,})$',
      ).hasMatch(normalized) ||
      (identifier.toLowerCase().startsWith('test') && normalized == 'test');
}

bool _isExplicitEmptySentinel(String identifier, String literal) =>
    identifier.toLowerCase().startsWith('empty') &&
    _emptySentinelLiteral.hasMatch(literal.trim());
