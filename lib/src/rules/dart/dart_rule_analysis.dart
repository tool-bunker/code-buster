// One analyzer traversal collects the Dart facts needed by many rules, avoiding repeated parsing and inconsistent interpretations.

import 'package:analyzer/dart/analysis/features.dart';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../catalog/rule_catalog.dart';
import '../../core/models.dart';
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
      final String source = sources[path]!;
      result.addAll(_layoutFindings(path, source, maxLineLength));
      result.addAll(_currentDartStyleFindings(path, source));
      final CompilationUnit unit = units[path]!;
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
          RegExp(
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
          RegExp(r'[ \t]$').hasMatch(line)) {
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
      if (RegExp(r'\bRandom\s*\(').hasMatch(initializer.toSource())) {
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
          RegExp(r'runInShell\s*:\s*true'),
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
    final RegExpMatch? indexed = RegExp(
      r'^([A-Za-z_]\w*)\[([A-Za-z_]\w*)\]$',
    ).firstMatch(lookup);
    if (indexed == null) return false;
    final String map = indexed.group(1)!;
    final String key = indexed.group(2)!;
    AstNode? current = node.parent;
    while (current != null) {
      if (current is ForStatement || current is ForElement) {
        return RegExp(
          'for\\s*\\([^)]*\\b${RegExp.escape(key)}\\s+in\\s+'
          '${RegExp.escape(map)}\\.keys\\b',
        ).hasMatch(current.toSource());
      }
      if (current is FunctionBody) return false;
      current = current.parent;
    }
    return false;
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
    if (RegExp(r'\brethrow\b').hasMatch(body)) return true;
    final String? error = node.exceptionParameter?.name.lexeme;
    final String? stack = node.stackTraceParameter?.name.lexeme;
    if (error == null || stack == null) return false;
    return RegExp(
      '\\bcompleteError\\s*\\(\\s*${RegExp.escape(error)}\\s*,\\s*'
      '${RegExp.escape(stack)}\\s*\\)',
    ).hasMatch(body);
  }

  static final RegExp _sensitiveName = RegExp(
    r'password|secret|api_?key|access_?token|auth_?token|token|nonce|private_?key',
    caseSensitive: false,
  );
  static final RegExp _testSourcePath = RegExp(
    r'(?:^|/)(?:test|tests)(?:/|$)|_test\.dart$',
    caseSensitive: false,
  );
  static final RegExp _numberedFixtureCredential = RegExp(
    r'^[a-z]+(?:[-_][a-z]+)+[-_]\d{1,6}$',
    caseSensitive: false,
  );
  static final RegExp _graphQlOperation = RegExp(
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
    if (RegExp(r'^[A-Za-z][A-Za-z0-9]*$').hasMatch(normalized) &&
        !RegExp(r'\d').hasMatch(normalized)) {
      return false;
    }
    final bool hasLower = RegExp('[a-z]').hasMatch(normalized);
    final bool hasUpper = RegExp('[A-Z]').hasMatch(normalized);
    final bool hasDigit = RegExp(r'\d').hasMatch(normalized);
    return hasLower && (hasUpper || hasDigit);
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
