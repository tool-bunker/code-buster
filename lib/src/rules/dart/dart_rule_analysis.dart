// One analyzer traversal collects the Dart facts needed by many rules, avoiding repeated parsing and inconsistent interpretations.

import 'package:analyzer/dart/analysis/features.dart';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../catalog/rule_catalog.dart';
import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import 'dart_advanced_rules.dart';
import 'dart_mvvm_rules.dart';

/// Core style, suspicious-code, security, and idiomatic rules for Dart sources.
final class DartRuleAnalysis {
  /// Analyzes project-relative Dart [sources].
  List<Finding> findings(
    Map<String, String> sources, {
    AnalysisConfig? config,
    int maxLineLength = 80,
  }) => findingsParsed(
    sources,
    <String, CompilationUnit>{
      for (final MapEntry<String, String> source in sources.entries)
        source.key: parseString(
          content: source.value,
          path: source.key,
          featureSet: FeatureSet.latestLanguageVersion(),
          throwIfDiagnostics: false,
        ).unit,
    },
    config: config,
    maxLineLength: maxLineLength,
  );

  /// Analyzes sources using compilation units already parsed by the plugin.
  List<Finding> findingsParsed(
    Map<String, String> sources,
    Map<String, CompilationUnit> units, {
    AnalysisConfig? config,
    int maxLineLength = 80,
  }) {
    final List<Finding> result = <Finding>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String path in paths) {
      final String? source = sources[path];
      final CompilationUnit? unit = units[path];
      if (source == null || unit == null) continue;
      result.addAll(_layoutFindings(path, source, maxLineLength));
      result.addAll(_currentDartStyleFindings(path, source));
      final _DartRuleVisitor visitor = _DartRuleVisitor(path, source);
      unit.accept(visitor);
      result.addAll(
        visitor.findings.where(
          (Finding finding) =>
              config == null ||
              config.severityOverrides.containsKey(finding.code) ||
              config.ruleGroups.contains(
                RuleCatalog.lookup(finding.code)?.group ?? '',
              ),
        ),
      );
      result.addAll(
        DartAdvancedRuleAnalysis().findings(
          <String, String>{path: source},
          <String, CompilationUnit>{path: unit},
        ),
      );
      if (config != null) {
        result.removeWhere(
          (Finding finding) =>
              finding.code.startsWith('dart-') &&
              !config.severityOverrides.containsKey(finding.code) &&
              !config.ruleGroups.contains(
                RuleCatalog.lookup(finding.code)?.group ?? '',
              ),
        );
      }
    }
    if (config != null) {
      result.addAll(DartMvvmRuleAnalysis().findings(sources, config));
    }
    if (config != null) {
      result.addAll(
        DartAdvancedRuleAnalysis().repositoryFindings(sources, units, config),
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  List<Finding> _currentDartStyleFindings(String path, String source) {
    final List<Finding> result = <Finding>[];
    final List<String> lines = source.split('\n');
    var asyncDepth = 0;
    for (var index = 0; index < lines.length; index++) {
      final String raw = lines[index];
      final String line = raw.trim();
      if (line.startsWith('// ignore:') ||
          line.startsWith('// ignore_for_file:')) {
        result.add(
          _lineFinding(
            'dart-analyzer-ignore',
            RuleSeverity.info,
            path,
            index + 1,
            'Dart analyzer diagnostic suppressed',
          ),
        );
      }
      if (line.contains(' async') || line.startsWith('async ')) asyncDepth = 1;
      if (asyncDepth > 0) {
        asyncDepth += '{'.allMatches(raw).length - '}'.allMatches(raw).length;
      }
      if (asyncDepth > 0 &&
          cachedRegExp(
            r'\b(?:sleep|readAsStringSync|writeAsStringSync|readAsBytesSync)\s*\(',
          ).hasMatch(line)) {
        result.add(
          _lineFinding(
            'dart-blocking-in-async',
            RuleSeverity.warn,
            path,
            index + 1,
            'blocking operation used in async code',
          ),
        );
      }
      if (asyncDepth > 0 && line.startsWith('}')) asyncDepth = 0;
    }
    return result;
  }

  Finding _lineFinding(
    String code,
    RuleSeverity severity,
    String path,
    int line,
    String message,
  ) => Finding(
    code: code,
    severity: severity,
    path: path,
    line: line,
    endLine: line,
    message: message,
    confidence: 'medium',
    why:
        'This Dart construct can weaken static safety, reliability, or security.',
    suggestion:
        'Use the safer typed asynchronous Dart pattern described by the rule.',
  );

  List<Finding> _layoutFindings(
    String sourcePath,
    String source,
    int maxLineLength,
  ) {
    final List<Finding> result = <Finding>[];
    final List<String> lines = source.split('\n');
    String? tripleQuote;
    final String tripleDoubleQuote = '"' * 3;
    for (var index = 0; index < lines.length; index++) {
      final String line = lines[index];
      final String trimmed = line.trimLeft();
      final bool insideTripleString = tripleQuote != null;
      for (final String delimiter in <String>["'''", tripleDoubleQuote]) {
        if (delimiter.allMatches(line).length.isOdd) {
          tripleQuote = tripleQuote == null ? delimiter : null;
        }
      }
      final bool unwrappable =
          insideTripleString ||
          tripleQuote != null ||
          trimmed.startsWith('//') ||
          trimmed.startsWith('/*') ||
          trimmed.startsWith('*') ||
          trimmed.startsWith('import ') ||
          trimmed.startsWith('export ') ||
          trimmed.startsWith('part ') ||
          trimmed.contains("'") ||
          trimmed.contains('"');
      final bool commentLine =
          trimmed.startsWith('//') ||
          trimmed.startsWith('/*') ||
          trimmed.startsWith('*');
      if (!insideTripleString &&
          tripleQuote == null &&
          !commentLine &&
          line.substring(0, line.length - trimmed.length).contains('\t')) {
        result.add(
          Finding(
            code: 'tab-indent',
            severity: RuleSeverity.warn,
            path: sourcePath,
            line: index + 1,
            endLine: index + 1,
            message: 'tab character used for indentation/alignment',
            confidence: 'high',
            why:
                'Tabs render differently across editors and many project styles forbid tab indentation.',
            suggestion: 'Use spaces for indentation.',
          ),
        );
      }
      if (!insideTripleString &&
          tripleQuote == null &&
          line.isNotEmpty &&
          cachedRegExp(r'[ \t]$').hasMatch(line)) {
        result.add(
          Finding(
            code: 'trailing-whitespace',
            severity: RuleSeverity.info,
            path: sourcePath,
            line: index + 1,
            endLine: index + 1,
            message: 'line has trailing whitespace',
            confidence: 'high',
            why: 'Trailing whitespace creates noisy diffs.',
            suggestion: 'Trim trailing spaces before committing.',
          ),
        );
      }
      if (maxLineLength > 0 && line.length > maxLineLength && !unwrappable) {
        result.add(
          Finding(
            code: 'long-line',
            severity: RuleSeverity.info,
            path: sourcePath,
            line: index + 1,
            endLine: index + 1,
            message: 'line length ${line.length} > $maxLineLength',
            confidence: 'high',
            why: 'Shorter lines are easier to scan and review.',
            suggestion:
                'Wrap the expression/call using normal language indentation conventions.',
          ),
        );
      }
    }
    return result;
  }
}

final class _DartRuleVisitor extends RecursiveAstVisitor<void> {
  _DartRuleVisitor(this.path, this.source);

  final String path;
  final String source;
  final List<Finding> findings = <Finding>[];
  final Set<int> _nullAssertionLines = <int>{};

  @override
  void visitBlock(Block node) {
    final NodeList<Statement> statements = node.statements;
    for (var index = 0; index + 1 < statements.length; index++) {
      if (_terminatesFlow(statements[index])) {
        _add(
          statements[index + 1],
          code: 'dart-unreachable-statement',
          severity: RuleSeverity.warn,
          message: 'statement is unreachable after unconditional control flow',
          confidence: 'high',
          why:
              'Code after return, throw, break, or continue cannot execute and often hides a disabled implementation.',
          suggestion:
              'Remove the unreachable code or restore the intended branch.',
        );
        break;
      }
    }
    super.visitBlock(node);
  }

  @override
  void visitNamedType(NamedType node) {
    if (node.toSource() == 'dynamic') {
      _add(
        node,
        code: 'dart-dynamic',
        severity: RuleSeverity.warn,
        message: 'dynamic disables static type checking at this boundary',
        confidence: 'high',
        suggestion:
            'Use an explicit type, Object?, or a constrained generic parameter.',
      );
    }
    super.visitNamedType(node);
  }

  @override
  void visitVariableDeclarationList(VariableDeclarationList node) {
    if (node.isLate && !node.isFinal) {
      _add(
        node,
        code: 'dart-late-mutable',
        severity: RuleSeverity.info,
        message: 'mutable late variable used',
        confidence: 'medium',
        suggestion:
            'Use late final when the variable is assigned exactly once, or initialize it eagerly.',
      );
    }
    super.visitVariableDeclarationList(node);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final String name = node.name.lexeme;
    final Expression? initializer = node.initializer;
    if (initializer != null && _sensitiveName.hasMatch(name)) {
      final String? literal = _stringLiteralValue(initializer);
      if (literal != null &&
          _looksLikeSecret(literal) &&
          !_isPublicProtocolIdentifier(name, literal) &&
          !_looksLikeGraphQlDocument(literal) &&
          !_isDeterministicTestFixtureSecret(literal)) {
        _add(
          node,
          code: 'dart-hardcoded-secret',
          severity: RuleSeverity.warn,
          message: 'possible hardcoded secret assigned to `$name`',
          confidence: 'high',
          why:
              'Credential-like literals in source can leak through version control and build artifacts.',
          suggestion:
              'Load the value from a secret manager or environment configuration.',
        );
      }
      if (cachedRegExp(r'\bRandom\s*\(').hasMatch(initializer.toSource())) {
        _add(
          node,
          code: 'dart-insecure-random',
          severity: RuleSeverity.warn,
          message: 'non-cryptographic Random used for security-sensitive value',
          confidence: 'high',
          why:
              'dart:math Random is predictable and unsuitable for credentials or nonces.',
          suggestion: 'Use Random.secure() or a cryptographic library.',
        );
      }
    }
    super.visitVariableDeclaration(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String method = node.methodName.name;
    if (method == 'print' &&
        node.target == null &&
        !_isCommandLineEntrypointOutput(node)) {
      _add(
        node,
        code: 'dart-print',
        severity: RuleSeverity.info,
        message: 'print call left in application code',
        confidence: 'medium',
        why:
            'Unstructured console output can leak data and is difficult to control in production.',
        suggestion: 'Use a structured logger or remove temporary diagnostics.',
      );
    }
    final String? target = node.target?.toSource();
    if (target == 'Process' &&
        const <String>{'run', 'start'}.contains(method) &&
        node.argumentList.toSource().contains(
          cachedRegExp(r'runInShell\s*:\s*true'),
        )) {
      _add(
        node,
        code: 'dart-process-shell',
        severity: RuleSeverity.warn,
        message: 'process launched through a shell',
        confidence: 'high',
        suggestion: 'Keep runInShell false and pass arguments as a list.',
      );
    }
    super.visitMethodInvocation(node);
  }

  bool _isCommandLineEntrypointOutput(MethodInvocation node) {
    if (!path.startsWith('bin/') && !path.startsWith('tool/')) return false;
    AstNode? current = node.parent;
    while (current != null && current is! FunctionDeclaration) {
      current = current.parent;
    }
    return current is FunctionDeclaration && current.name.lexeme == 'main';
  }

  @override
  void visitPostfixExpression(PostfixExpression node) {
    final int line = _lineAt(node.offset);
    if (node.operator.lexeme == '!' &&
        _isReportedNullAssertionSyntax(node) &&
        !_isGuaranteedWholeMatch(node) &&
        !_isKeyProvenPresent(node) &&
        !_isProvenNonNullByControlFlow(node) &&
        _nullAssertionLines.add(line)) {
      _add(
        node,
        code: 'dart-null-assertion',
        severity: RuleSeverity.info,
        message: 'null assertion used',
        confidence: 'medium',
        why:
            'A null assertion converts an unchecked nullable value into a runtime failure.',
        suggestion:
            'Use promotion, pattern matching, or explicit fallback handling instead.',
      );
    }
    super.visitPostfixExpression(node);
  }

  bool _isReportedNullAssertionSyntax(PostfixExpression node) {
    var offset = node.end;
    while (offset < source.length &&
        const <String>{' ', '\t'}.contains(source[offset])) {
      offset++;
    }
    return offset < source.length &&
        const <String>{'.', ';', ')', ']'}.contains(source[offset]);
  }

  bool _isGuaranteedWholeMatch(PostfixExpression node) {
    final Expression operand = node.operand;
    if (operand is! MethodInvocation ||
        operand.methodName.name != 'group' ||
        operand.argumentList.arguments.length != 1) {
      return false;
    }
    final Argument argument = operand.argumentList.arguments.single;
    return argument is IntegerLiteral && argument.value == 0;
  }

  bool _isKeyProvenPresent(PostfixExpression node) {
    final String lookup = node.operand.toSource();
    final RegExpMatch? indexed = cachedRegExp(
      r'^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\[([A-Za-z_]\w*)\]$',
    ).firstMatch(lookup);
    if (indexed == null) return false;
    final String map = indexed.requiredGroup(1);
    final String key = indexed.requiredGroup(2);
    AstNode? current = node.parent;
    while (current != null) {
      if (current is ForStatement || current is ForElement) {
        return cachedRegExp(
          'for\\s*\\([^;{}]*\\b${RegExp.escape(key)}\\s+in\\s+'
          '${RegExp.escape(map)}\\.keys'
          '(?:\\.toList\\(\\)\\.\\.sort\\(\\))?\\s*\\)',
        ).hasMatch(current.toSource());
      }
      if (current is FunctionBody) return false;
      current = current.parent;
    }
    return false;
  }

  bool _isProvenNonNullByControlFlow(PostfixExpression node) {
    final String target = node.operand.toSource();
    if (!cachedRegExp(
      r'^(?:[A-Za-z_]\w*)(?:\.[A-Za-z_]\w*|\[[^\]]+\])*$',
    ).hasMatch(target)) {
      return false;
    }
    final List<({Expression expression, bool expected})> constraints =
        <({Expression expression, bool expected})>[];
    AstNode child = node;
    AstNode? current = node.parent;
    while (current != null && current is! FunctionBody) {
      if (current case final IfStatement statement) {
        if (_containsNode(statement.thenStatement, child)) {
          constraints.add((expression: statement.expression, expected: true));
        } else if (statement.elseStatement case final Statement otherwise
            when _containsNode(otherwise, child)) {
          constraints.add((expression: statement.expression, expected: false));
        }
      } else if (current case final ConditionalExpression conditional) {
        if (_containsNode(conditional.thenExpression, child)) {
          constraints.add((expression: conditional.condition, expected: true));
        } else if (_containsNode(conditional.elseExpression, child)) {
          constraints.add((expression: conditional.condition, expected: false));
        }
      } else if (current case final BinaryExpression binary) {
        if (_containsNode(binary.rightOperand, child)) {
          if (binary.operator.lexeme == '&&') {
            constraints.add((expression: binary.leftOperand, expected: true));
          } else if (binary.operator.lexeme == '||') {
            constraints.add((expression: binary.leftOperand, expected: false));
          }
        }
      } else if (current case final Block block) {
        final int statementIndex = block.statements.indexWhere(
          (Statement statement) => _containsNode(statement, child),
        );
        if (statementIndex >= 0) {
          for (var index = statementIndex - 1; index >= 0; index--) {
            final Statement previous = block.statements[index];
            if (_writesExpression(previous, target)) break;
            if (previous case final IfStatement guard) {
              final bool thenExits = _alwaysExits(guard.thenStatement);
              final bool elseExits =
                  guard.elseStatement != null &&
                  _alwaysExits(guard.elseStatement!);
              if (thenExits && !elseExits) {
                constraints.add((
                  expression: guard.expression,
                  expected: false,
                ));
              } else if (elseExits && !thenExits) {
                constraints.add((expression: guard.expression, expected: true));
              }
            }
          }
        }
      }
      child = current;
      current = current.parent;
    }
    if (constraints.isEmpty) return false;

    final Map<String, Expression> getterConditions = _getterConditions(node);
    final Set<String> atoms = <String>{};
    for (final ({Expression expression, bool expected}) constraint
        in constraints) {
      _collectConditionAtoms(
        constraint.expression,
        target,
        getterConditions,
        atoms,
        <String>{},
      );
    }
    if (atoms.length > 12) return false;
    final List<String> atomList = atoms.toList(growable: false);
    final int assignmentCount = 1 << atomList.length;
    for (var mask = 0; mask < assignmentCount; mask++) {
      final Map<String, bool> assignment = <String, bool>{
        for (var index = 0; index < atomList.length; index++)
          atomList[index]: mask & (1 << index) != 0,
      };
      final bool reachable = constraints.every(
        (({Expression expression, bool expected}) constraint) =>
            _evaluateCondition(
              constraint.expression,
              target,
              getterConditions,
              assignment,
              <String>{},
            ) ==
            constraint.expected,
      );
      if (reachable) return false;
    }
    return true;
  }

  bool _containsNode(AstNode container, AstNode node) =>
      container.offset <= node.offset && node.end <= container.end;

  bool _writesExpression(Statement statement, String target) {
    final String escaped = RegExp.escape(target);
    return cachedRegExp(
      '(?:^|[^=!<>])\\b$escaped\\s*(?:=(?!=)|\\+\\+|--|\\?\\?=)',
    ).hasMatch(statement.toSource());
  }

  bool _alwaysExits(Statement statement) {
    if (statement is ReturnStatement ||
        statement is BreakStatement ||
        statement is ContinueStatement) {
      return true;
    }
    if (statement case final ExpressionStatement expressionStatement) {
      return expressionStatement.expression is ThrowExpression;
    }
    if (statement case final Block block when block.statements.isNotEmpty) {
      return _alwaysExits(block.statements.last);
    }
    return false;
  }

  Map<String, Expression> _getterConditions(AstNode node) {
    AstNode? current = node.parent;
    while (current != null && current is! ClassDeclaration) {
      current = current.parent;
    }
    if (current is! ClassDeclaration) return const <String, Expression>{};
    final Map<String, Expression> result = <String, Expression>{};
    for (final MethodDeclaration method
        in current.body.members.whereType<MethodDeclaration>()) {
      if (!method.isGetter) continue;
      final FunctionBody body = method.body;
      if (body case final ExpressionFunctionBody expressionBody) {
        result[method.name.lexeme] = expressionBody.expression;
      } else if (body case final BlockFunctionBody blockBody) {
        final List<Statement> statements = blockBody.block.statements;
        if (statements.length == 1) {
          final Statement statement = statements.single;
          if (statement is ReturnStatement && statement.expression != null) {
            result[method.name.lexeme] = statement.expression!;
          }
        }
      }
    }
    return result;
  }

  void _collectConditionAtoms(
    Expression expression,
    String target,
    Map<String, Expression> getterConditions,
    Set<String> atoms,
    Set<String> expandingGetters,
  ) {
    if (expression case final ParenthesizedExpression parenthesized) {
      _collectConditionAtoms(
        parenthesized.expression,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      return;
    }
    if (expression case final PrefixExpression prefix
        when prefix.operator.lexeme == '!') {
      _collectConditionAtoms(
        prefix.operand,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      return;
    }
    if (expression case final BinaryExpression binary
        when binary.operator.lexeme == '&&' || binary.operator.lexeme == '||') {
      _collectConditionAtoms(
        binary.leftOperand,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      _collectConditionAtoms(
        binary.rightOperand,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      return;
    }
    if (_nullComparisonValue(expression, target) != null ||
        _mapPresenceValue(expression, target) != null ||
        expression is BooleanLiteral) {
      return;
    }
    final String source = expression.toSource();
    final Expression? getter = getterConditions[source];
    if (getter != null && expandingGetters.add(source)) {
      _collectConditionAtoms(
        getter,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      expandingGetters.remove(source);
      return;
    }
    atoms.add(source);
  }

  bool _evaluateCondition(
    Expression expression,
    String target,
    Map<String, Expression> getterConditions,
    Map<String, bool> atoms,
    Set<String> expandingGetters,
  ) {
    if (expression case final ParenthesizedExpression parenthesized) {
      return _evaluateCondition(
        parenthesized.expression,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
    }
    if (expression case final PrefixExpression prefix
        when prefix.operator.lexeme == '!') {
      return !_evaluateCondition(
        prefix.operand,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
    }
    if (expression case final BinaryExpression binary) {
      if (binary.operator.lexeme == '&&') {
        return _evaluateCondition(
              binary.leftOperand,
              target,
              getterConditions,
              atoms,
              expandingGetters,
            ) &&
            _evaluateCondition(
              binary.rightOperand,
              target,
              getterConditions,
              atoms,
              expandingGetters,
            );
      }
      if (binary.operator.lexeme == '||') {
        return _evaluateCondition(
              binary.leftOperand,
              target,
              getterConditions,
              atoms,
              expandingGetters,
            ) ||
            _evaluateCondition(
              binary.rightOperand,
              target,
              getterConditions,
              atoms,
              expandingGetters,
            );
      }
    }
    final bool? comparison = _nullComparisonValue(expression, target);
    if (comparison != null) return comparison;
    final bool? presence = _mapPresenceValue(expression, target);
    if (presence != null) return presence;
    if (expression case final BooleanLiteral literal) return literal.value;
    final String source = expression.toSource();
    final Expression? getter = getterConditions[source];
    if (getter != null && expandingGetters.add(source)) {
      final bool value = _evaluateCondition(
        getter,
        target,
        getterConditions,
        atoms,
        expandingGetters,
      );
      expandingGetters.remove(source);
      return value;
    }
    return atoms.requiredValue(source);
  }

  bool? _nullComparisonValue(Expression expression, String target) {
    if (expression is! BinaryExpression ||
        expression.operator.lexeme != '==' &&
            expression.operator.lexeme != '!=') {
      return null;
    }
    final bool comparesTarget =
        expression.leftOperand.toSource() == target &&
            expression.rightOperand is NullLiteral ||
        expression.rightOperand.toSource() == target &&
            expression.leftOperand is NullLiteral;
    if (!comparesTarget) return null;
    return expression.operator.lexeme == '==';
  }

  bool? _mapPresenceValue(Expression expression, String target) {
    final RegExpMatch? lookup = cachedRegExp(
      r'^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\[([A-Za-z_]\w*)\]$',
    ).firstMatch(target);
    if (lookup == null) return null;
    final String map = lookup.requiredGroup(1);
    final String key = lookup.requiredGroup(2);
    return expression.toSource() == '$map.containsKey($key)' ? false : null;
  }

  @override
  void visitCatchClause(CatchClause node) {
    if (node.exceptionType == null && !_forwardsCaughtFailure(node)) {
      _add(
        node,
        code: 'dart-broad-catch',
        severity: RuleSeverity.warn,
        message: 'catch clause catches every exception type',
        confidence: 'high',
        suggestion:
            'Catch a specific exception type or rethrow unexpected failures.',
      );
    }
    super.visitCatchClause(node);
  }

  bool _forwardsCaughtFailure(CatchClause node) {
    final String body = node.body.toSource();
    if (cachedRegExp(r'\brethrow\b').hasMatch(body)) return true;
    final String? error = node.exceptionParameter?.name.lexeme;
    final String? stack = node.stackTraceParameter?.name.lexeme;
    if (error == null || stack == null) return false;
    return cachedRegExp(
      '\\bcompleteError\\s*\\(\\s*${RegExp.escape(error)}\\s*,\\s*'
      '${RegExp.escape(stack)}\\s*\\)',
    ).hasMatch(body);
  }

  static final RegExp _sensitiveName = cachedRegExp(
    r'password|secret|api_?key|access_?token|auth_?token|token|nonce|private_?key',
    caseSensitive: false,
  );
  static final RegExp _testSourcePath = cachedRegExp(
    r'(?:^|/)(?:test|tests)(?:/|$)|_test\.dart$',
    caseSensitive: false,
  );
  static final RegExp _numberedFixtureCredential = cachedRegExp(
    r'^[a-z]+(?:[-_][a-z]+)+[-_]\d{1,6}$',
    caseSensitive: false,
  );
  static final RegExp _graphQlOperation = cachedRegExp(
    r'^(?:query|mutation|subscription|fragment)\b',
  );

  String? _stringLiteralValue(Expression expression) => switch (expression) {
    SimpleStringLiteral(:final String value) => value,
    _ => null,
  };

  bool _looksLikeSecret(String value) {
    final String normalized = value.trim();
    final String lower = normalized.toLowerCase();
    if (normalized.contains('-----BEGIN ') &&
        normalized.contains('PRIVATE KEY-----')) {
      return true;
    }
    if (normalized.length < 12 ||
        const <String>{
          'password',
          'changeme',
          'your-secret',
          'your_api_key',
          'placeholder',
          'example',
        }.contains(lower)) {
      return false;
    }
    if (cachedRegExp(r'^[A-Za-z][A-Za-z0-9]*$').hasMatch(normalized) &&
        !cachedRegExp(r'\d').hasMatch(normalized)) {
      return false;
    }
    final bool hasLower = cachedRegExp('[a-z]').hasMatch(normalized);
    final bool hasUpper = cachedRegExp('[A-Z]').hasMatch(normalized);
    final bool hasDigit = cachedRegExp(r'\d').hasMatch(normalized);
    return hasLower && (hasUpper || hasDigit);
  }

  bool _isPublicProtocolIdentifier(String name, String value) {
    final String lowerName = name.toLowerCase();
    return Uri.tryParse(value)?.hasScheme == true ||
        lowerName.contains('useragent') ||
        lowerName.contains('user_agent');
  }

  bool _looksLikeGraphQlDocument(String value) =>
      _graphQlOperation.hasMatch(value.trimLeft());

  bool _isDeterministicTestFixtureSecret(String value) =>
      _testSourcePath.hasMatch(path) &&
      _numberedFixtureCredential.hasMatch(value.trim());

  bool _terminatesFlow(Statement statement) =>
      statement is ReturnStatement ||
      statement is BreakStatement ||
      statement is ContinueStatement ||
      (statement is ExpressionStatement &&
          (statement.expression is ThrowExpression ||
              statement.expression is RethrowExpression));

  void _add(
    AstNode node, {
    required String code,
    required RuleSeverity severity,
    required String message,
    required String confidence,
    String why = '',
    required String suggestion,
  }) {
    findings.add(
      Finding(
        code: code,
        severity: severity,
        path: path,
        line: _lineAt(node.offset),
        endLine: _lineAt(node.end),
        message: message,
        confidence: confidence,
        why: why,
        suggestion: suggestion,
      ),
    );
  }

  int _lineAt(int offset) =>
      '\n'.allMatches(source.substring(0, offset)).length + 1;
}
