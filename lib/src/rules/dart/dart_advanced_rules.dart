// Framework hooks, serialization, async state, and API misuse require richer Dart syntax evidence than line-oriented checks can provide.

import 'dart:io';

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:path/path.dart' as path;

import '../../core/models.dart';

part 'dart_lifecycle_rules.dart';
part 'dart_flutter_build_rules.dart';

/// Repository, ownership, security, Flutter lifecycle, and data-contract rules
/// that are intentionally outside the Dart analyzer's local lint surface.
final class DartAdvancedRuleAnalysis {
  /// Analyzes already parsed Dart compilation units.
  List<Finding> findings(
    Map<String, String> sources,
    Map<String, CompilationUnit> units, {
    AnalysisConfig? config,
  }) {
    final List<Finding> result = <Finding>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String path in paths) {
      final _AdvancedDartVisitor visitor = _AdvancedDartVisitor(
        path,
        sources[path]!,
      );
      units[path]!.accept(visitor);
      result.addAll(visitor.findings);
    }
    if (config != null) {
      result.addAll(_analyzerCoverage(config, sources.keys));
    }
    return List<Finding>.unmodifiable(result);
  }

  /// Runs checks that require all compilation units in the repository.
  List<Finding> repositoryFindings(
    Map<String, String> sources,
    Map<String, CompilationUnit> units,
    AnalysisConfig config,
  ) => List<Finding>.unmodifiable(<Finding>[
    if (config.duplicationMode == DuplicationMode.semantic)
      ..._overlappingModels(sources, units),
    ..._analyzerCoverage(config, sources.keys),
  ]);

  List<Finding> _overlappingModels(
    Map<String, String> sources,
    Map<String, CompilationUnit> units,
  ) {
    final List<_DartModelShape> models = <_DartModelShape>[];
    for (final String path in units.keys.toList()..sort()) {
      for (final ClassDeclaration declaration
          in units[path]!.declarations.whereType<ClassDeclaration>()) {
        final Set<String> fields = declaration.body.members
            .whereType<FieldDeclaration>()
            .where((FieldDeclaration field) => !field.isStatic)
            .expand(
              (FieldDeclaration field) => field.fields.variables.map(
                (VariableDeclaration variable) => variable.name.lexeme,
              ),
            )
            .where((String name) => !name.startsWith('_'))
            .toSet();
        if (fields.length < 4) continue;
        models.add(
          _DartModelShape(
            path: path,
            name: declaration.namePart.typeName.lexeme,
            line:
                '\n'
                    .allMatches(sources[path]!.substring(0, declaration.offset))
                    .length +
                1,
            fields: fields,
            parent: declaration.extendsClause?.superclass.toSource(),
          ),
        );
      }
    }

    final List<Finding> findings = <Finding>[];
    for (var leftIndex = 0; leftIndex < models.length; leftIndex++) {
      final _DartModelShape left = models[leftIndex];
      for (
        var rightIndex = leftIndex + 1;
        rightIndex < models.length;
        rightIndex++
      ) {
        final _DartModelShape right = models[rightIndex];
        if (left.path == right.path ||
            left.name == right.parent ||
            right.name == left.parent) {
          continue;
        }
        final Set<String> shared = left.fields.intersection(right.fields);
        final int unionSize = left.fields.union(right.fields).length;
        if (shared.length < 4 || shared.length * 5 < unionSize * 4) continue;
        final List<String> orderedShared = shared.toList()..sort();
        findings.add(
          Finding(
            code: 'dart-overlapping-data-model',
            severity: RuleSeverity.info,
            path: left.path,
            line: left.line,
            endLine: left.line,
            message:
                '${left.name} and ${right.name} duplicate ${shared.length} data fields',
            confidence: 'medium',
            why:
                'Separate data models with at least 80% field overlap can drift while representing the same concept.',
            suggestion:
                'Confirm that the models have distinct contracts; otherwise share one model or an explicit common value object.',
            relatedFiles: <String>['${right.path}:${right.line}'],
            snippet:
                'shared fields: ${orderedShared.join(', ')}; overlap: ${shared.length}/$unionSize',
          ),
        );
      }
    }
    return findings;
  }

  List<Finding> _analyzerCoverage(
    AnalysisConfig config,
    Iterable<String> sourcePaths,
  ) {
    final List<String> analyzableSources = sourcePaths
        .where(
          (String sourcePath) => !RegExp(
            r'(^|/)(?:__tests__|test|tests)/fixtures(?:/|$)',
          ).hasMatch(sourcePath.replaceAll(r'\', '/')),
        )
        .toList(growable: false);
    if (analyzableSources.isEmpty) return const <Finding>[];
    final String root = path.normalize(path.absolute(config.root));
    final Set<String> packageRoots = <String>{};
    for (final String sourcePath in analyzableSources) {
      var directory = path.dirname(path.join(root, sourcePath));
      while (directory == root || path.isWithin(root, directory)) {
        if (File(path.join(directory, 'pubspec.yaml')).existsSync()) {
          packageRoots.add(directory);
          break;
        }
        if (directory == root) break;
        directory = path.dirname(directory);
      }
    }

    final List<Finding> findings = <Finding>[];
    for (final String packageRoot in packageRoots.toList()..sort()) {
      final String relativeRoot = path.relative(packageRoot, from: root);
      final String optionsPath = relativeRoot == '.'
          ? 'analysis_options.yaml'
          : path.join(relativeRoot, 'analysis_options.yaml');
      final File options = File(
        path.join(packageRoot, 'analysis_options.yaml'),
      );
      if (!options.existsSync()) {
        findings.add(
          _finding(
            code: 'dart-recommended-lints-missing',
            path: optionsPath,
            line: 1,
            message: 'analysis_options.yaml is missing',
            why: 'Dart analyzer coverage is not configured for this package.',
            suggestion: 'Add the recommended Dart or Flutter lint set.',
          ),
        );
        continue;
      }
      findings.addAll(_missingAnalyzerRules(options, optionsPath));
    }
    return findings;
  }

  List<Finding> _missingAnalyzerRules(File options, String optionsPath) {
    final String source = options.readAsStringSync();
    final Set<String> missing = _recommendedAnalyzerRules
        .where(
          (String rule) => !RegExp(
            r'(?:^|\n)\s*(?:-\s*)?'
            '${RegExp.escape(rule)}'
            r'\s*(?::|$)',
            multiLine: true,
          ).hasMatch(source),
        )
        .toSet();
    if (source.contains('package:lints/recommended.yaml')) {
      missing.removeAll(_recommendedSetRules);
    }
    if (source.contains('package:flutter_lints/flutter.yaml')) {
      missing.removeAll(_flutterLintSetRules);
    }
    if (missing.isEmpty) return const <Finding>[];
    return <Finding>[
      _finding(
        code: 'dart-recommended-lints-missing',
        path: optionsPath,
        line: 1,
        message:
            'important analyzer coverage is missing: ${missing.toList()..sort()}',
        why:
            'Code Buster should complement rather than duplicate Dart analyzer checks.',
        suggestion:
            'Enable the missing analyzer rules in analysis_options.yaml.',
      ),
    ];
  }

  static const Set<String> _recommendedAnalyzerRules = <String>{
    'cancel_subscriptions',
    'close_sinks',
    'discarded_futures',
    'implementation_imports',
    'unawaited_futures',
    'use_build_context_synchronously',
    'use_rethrow_when_possible',
  };

  static const Set<String> _recommendedSetRules = <String>{
    'implementation_imports',
    'use_rethrow_when_possible',
  };

  static const Set<String> _flutterLintSetRules = <String>{
    ..._recommendedSetRules,
    'use_build_context_synchronously',
  };
}

final class _DartModelShape {
  const _DartModelShape({
    required this.path,
    required this.name,
    required this.line,
    required this.fields,
    required this.parent,
  });

  final String path;
  final String name;
  final int line;
  final Set<String> fields;
  final String? parent;
}

final class _PreservedCopyFieldVisitor extends RecursiveAstVisitor<void> {
  _PreservedCopyFieldVisitor(this.candidates);

  final Set<String> candidates;
  final Set<String> fields = <String>{};

  @override
  void visitNamedArgument(NamedArgument node) {
    final String label = node.name.lexeme;
    final String value = node.argumentExpression.toSource();
    if (candidates.contains(label) &&
        RegExp(
          '(?:^|\\W)(?:this\\.)?${RegExp.escape(label)}(?:\\W|\$)',
        ).hasMatch(value)) {
      fields.add(label);
    }
    super.visitNamedArgument(node);
  }

  @override
  void visitCascadeExpression(CascadeExpression node) {
    if (_isFreshCascadeTarget(node.target)) {
      for (final Expression section in node.cascadeSections) {
        if (section is! AssignmentExpression ||
            section.operator.lexeme != '=') {
          continue;
        }
        final RegExpMatch? assignment = RegExp(
          r'^\.\.([A-Za-z_]\w*)\s*=\s*(?:this\.)?([A-Za-z_]\w*)$',
        ).firstMatch(section.toSource());
        if (assignment != null &&
            assignment.group(1) == assignment.group(2) &&
            candidates.contains(assignment.group(1))) {
          fields.add(assignment.group(1)!);
        }
      }
    }
    super.visitCascadeExpression(node);
  }

  static bool _isFreshCascadeTarget(Expression target) =>
      target is InstanceCreationExpression ||
      (target is MethodInvocation &&
          target.target == null &&
          target.methodName.name.isNotEmpty &&
          target.methodName.name.codeUnitAt(0) >= 65 &&
          target.methodName.name.codeUnitAt(0) <= 90);
}

final class _AdvancedDartVisitor extends RecursiveAstVisitor<void> {
  _AdvancedDartVisitor(this.path, this.source);

  final String path;
  final String source;
  final List<Finding> findings = <Finding>[];
  final Set<AstNode> _reportedRegexLoops = <AstNode>{};
  final Map<String, bool> _fallbackDecoderCache = <String, bool>{};
  final Set<String> _topLevelLiteralSqlConstants = <String>{};
  final Map<String, Set<String>> _classLiteralSqlConstants =
      <String, Set<String>>{};

  @override
  void visitCompilationUnit(CompilationUnit node) {
    for (final CompilationUnitMember declaration in node.declarations) {
      if (declaration is TopLevelVariableDeclaration) {
        _recordLiteralSqlConstants(
          declaration.variables,
          _topLevelLiteralSqlConstants,
        );
      } else if (declaration is ClassDeclaration) {
        final Set<String> fields = <String>{};
        for (final FieldDeclaration member
            in declaration.body.members.whereType<FieldDeclaration>()) {
          if (member.isStatic) {
            _recordLiteralSqlConstants(member.fields, fields);
          }
        }
        if (fields.isNotEmpty) {
          _classLiteralSqlConstants[declaration.namePart.typeName.lexeme] =
              fields;
        }
      }
    }
    super.visitCompilationUnit(node);
  }

  void _recordLiteralSqlConstants(
    VariableDeclarationList declarations,
    Set<String> names,
  ) {
    if (declarations.keyword?.lexeme != 'const' ||
        declarations.type?.toSource() != 'String') {
      return;
    }
    for (final VariableDeclaration declaration in declarations.variables) {
      if (declaration.initializer is SimpleStringLiteral) {
        names.add(declaration.name.lexeme);
      }
    }
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    if (node.leftHandSide.toSource().endsWith('badCertificateCallback') &&
        RegExp(
          r'=>\s*true\b|return\s+true\s*;',
        ).hasMatch(node.rightHandSide.toSource())) {
      _add(
        node,
        code: 'dart-bad-certificate-callback',
        message: 'certificate callback accepts every certificate',
        why: 'Unconditional acceptance disables TLS peer authentication.',
        suggestion:
            'Remove the callback or validate the expected certificate identity.',
      );
    }
    super.visitAssignmentExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String method = node.methodName.name;
    final String target = node.target?.toSource() ?? '';
    if (_sqlMethods.contains(method) &&
        node.argumentList.arguments.any(_unsafeSqlArgument)) {
      _add(
        node,
        code: 'dart-sql-interpolation',
        message: 'interpolated SQL reaches `$method`',
        why: 'Interpolated SQL can allow injection and quoting defects.',
        suggestion: 'Use parameter placeholders and bound values.',
      );
    }
    if (target == 'Process' &&
        const <String>{
          'run',
          'start',
          'runSync',
          'startDetached',
        }.contains(method) &&
        _referencesPotentiallyUntrustedParameter(
          node.argumentList,
          node,
          _commandInputName,
        )) {
      _add(
        node,
        code: 'dart-process-untrusted-argument',
        message: 'function input reaches a process invocation',
        why:
            'Request or caller-controlled process arguments can invoke unintended programs or options.',
        suggestion:
            'Allowlist commands and validate each argument before execution.',
      );
    }
    if (_pathSinks.contains(method) &&
        (target == 'File' ||
            target == 'Directory' ||
            target == 'p' ||
            target == 'path') &&
        _referencesPotentiallyUntrustedParameter(
          node.argumentList,
          node,
          _pathInputName,
        )) {
      _add(
        node,
        code: 'dart-path-traversal',
        message: 'function input is used to construct a filesystem path',
        why:
            'Unvalidated path components can escape the intended root directory.',
        suggestion:
            'Canonicalize the path and verify containment under the allowed root.',
      );
    }
    if (target.isEmpty &&
        const <String>{'File', 'Directory'}.contains(method) &&
        _referencesPotentiallyUntrustedParameter(
          node.argumentList,
          node,
          _pathInputName,
        )) {
      _add(
        node,
        code: 'dart-path-traversal',
        message: 'function input is used as a filesystem path',
        why: 'Unvalidated paths can escape the intended storage root.',
        suggestion:
            'Canonicalize the path and verify containment under the allowed root.',
      );
    }
    if (_loggingMethods.contains(method) ||
        (method == 'print' && target.isEmpty)) {
      final _SensitiveIdentifierVisitor sensitive = _SensitiveIdentifierVisitor(
        _sensitiveName,
      );
      node.argumentList.accept(sensitive);
      if (sensitive.found) {
        _add(
          node,
          code: 'dart-sensitive-data-logging',
          message: 'sensitive value may be written to logs',
          why:
              'Credentials and authorization data persist in logs and telemetry.',
          suggestion:
              'Redact the sensitive field or log only non-secret metadata.',
        );
      }
    }
    final bool isFlutterSetState =
        method == 'setState' &&
        (target == 'this' ||
            (node.target == null &&
                !_enclosingParameterNames(node).contains('setState')));
    if (isFlutterSetState && _hasAwaitBefore(node) && !_hasMountedGuard(node)) {
      _add(
        node,
        code: 'flutter-set-state-after-await',
        message: 'setState occurs after an async gap without a mounted guard',
        why:
            'The State can be disposed while the asynchronous operation is pending.',
        suggestion:
            'Check mounted after the await and before calling setState.',
      );
    }
    if (method.endsWith('Sync') &&
        _syncFileMethods.contains(method) &&
        _isInAsyncFunction(node)) {
      _add(
        node,
        code: 'dart-synchronous-file-io-in-async',
        message:
            'synchronous filesystem operation `$method` runs in async code',
        why:
            'Synchronous filesystem access blocks the isolate and stalls unrelated asynchronous work.',
        suggestion: 'Use the asynchronous filesystem API and await its result.',
      );
    }
    if (method == 'watch' &&
        const <String>{'context', 'ref'}.contains(target) &&
        _isInsideEventCallback(node)) {
      _add(
        node,
        code: 'flutter-provider-watch-in-callback',
        message: '`$target.watch` is used inside an event callback',
        why:
            'Listening reads inside callbacks create unclear subscription timing and unnecessary rebuild coupling.',
        suggestion:
            'Use a non-listening read in the callback and watch during build.',
      );
    }
    final AstNode? regexLoop =
        method == 'RegExp' &&
            node.target == null &&
            node.argumentList.arguments.firstOrNull is SimpleStringLiteral
        ? _repeatedLoopAncestor(node)
        : null;
    if (regexLoop != null && _reportedRegexLoops.add(regexLoop)) {
      _add(
        node,
        code: 'dart-regexp-created-in-loop',
        message: 'constant RegExp is compiled during each loop iteration',
        why:
            'Repeated regular-expression compilation adds avoidable allocation and CPU work.',
        suggestion: 'Compile the RegExp once before entering the loop.',
      );
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final String type = node.constructorName.type.toSource();
    if (const <String>{'File', 'Directory'}.contains(type) &&
        _referencesPotentiallyUntrustedParameter(
          node.argumentList,
          node,
          _pathInputName,
        )) {
      _add(
        node,
        code: 'dart-path-traversal',
        message: 'function input is used as a filesystem path',
        why: 'Unvalidated paths can escape the intended storage root.',
        suggestion:
            'Canonicalize the path and verify containment under the allowed root.',
      );
    }
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitThrowExpression(ThrowExpression node) {
    if (node.expression is StringLiteral) {
      _add(
        node,
        code: 'dart-throw-string',
        message: 'a string is thrown instead of an exception',
        why:
            'Non-Exception values lose typed error semantics and are harder to handle correctly.',
        suggestion:
            'Throw an Exception or Error subtype with structured context.',
      );
    }
    super.visitThrowExpression(node);
  }

  @override
  void visitCatchClause(CatchClause node) {
    final String body = node.body.toSource();
    if (RegExp(r'\breturn\s+null\s*;').hasMatch(body) &&
        !_isIntentionalNullableFallback(node)) {
      _add(
        node,
        code: 'dart-catch-return-null',
        message: 'catch clause converts a failure to null',
        why:
            'Returning null erases the failure cause and makes operational errors ambiguous.',
        suggestion:
            'Return a typed result or rethrow after adding actionable context.',
      );
    }
    final String? exception = node.exceptionParameter?.name.lexeme;
    if (exception != null &&
        node.stackTraceParameter == null &&
        RegExp(
          '\\b(?:print|log|debug|info|warn|warning|error|severe)\\s*\\([^)]*\\b${RegExp.escape(exception)}\\b',
        ).hasMatch(body) &&
        !RegExp(r'\brethrow\b|\bthrow\b').hasMatch(body)) {
      _add(
        node,
        code: 'dart-catch-without-stack-trace',
        message: 'caught exception is logged without its stack trace',
        why:
            'Discarding the stack trace removes the call path needed to diagnose the failure.',
        suggestion:
            'Capture the stack trace with `catch (error, stackTrace)` and log both.',
      );
    }
    super.visitCatchClause(node);
  }

  bool _isIntentionalNullableFallback(CatchClause node) {
    AstNode? current = node.parent;
    while (current != null &&
        current is! MethodDeclaration &&
        current is! FunctionDeclaration) {
      current = current.parent;
    }
    final String? returnType = switch (current) {
      final MethodDeclaration method => method.returnType?.toSource(),
      final FunctionDeclaration function => function.returnType?.toSource(),
      _ => null,
    };
    return (returnType?.endsWith('?') ?? false) &&
        node.exceptionParameter == null &&
        node.body.statements.length == 1 &&
        node.body.statements.single is ReturnStatement;
  }

  @override
  void visitAsExpression(AsExpression node) {
    final String operand = node.expression.toSource();
    if (RegExp(r"\b(?:json|data|body|payload|map)\s*\[").hasMatch(operand) &&
        !_isProtectedByFallback(node) &&
        !_isFallbackProtectedDecoder(node) &&
        !_isGuardedByTypeTest(node)) {
      _add(
        node,
        code: 'dart-json-cast-without-validation',
        message: 'decoded JSON value is cast without validation',
        why: 'External JSON can contain null or a different runtime type.',
        suggestion:
            'Validate the value and produce a typed FormatException on mismatch.',
      );
    }
    super.visitAsExpression(node);
  }

  @override
  void visitClassDeclaration(ClassDeclaration node) {
    final String text = node.toSource();
    _checkOwnedResources(node, text);
    _checkListeners(node);
    _checkSerialization(node);
    _checkAsyncValuesInBuild(node);
    _checkPersistenceContracts(node, text);
    super.visitClassDeclaration(node);
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    if (!node.name.lexeme.startsWith('_') &&
        !node.name.lexeme.startsWith('toJson') &&
        RegExp(
          r'\bMap\s*<\s*String\s*,\s*dynamic\s*>',
        ).hasMatch(node.toSource().split(RegExp(r'=>|\{')).first)) {
      _add(
        node,
        code: 'dart-map-string-dynamic-boundary',
        message:
            'public method `${node.name.lexeme}` exposes Map<String, dynamic>',
        why:
            'Dynamic maps move schema failures from compile time to runtime across API boundaries.',
        suggestion:
            'Expose a typed model or Map<String, Object?> with explicit decoding.',
      );
    }
    _checkRepeatedTraversal(node);
    super.visitMethodDeclaration(node);
  }

  @override
  void visitForStatement(ForStatement node) {
    _checkLoop(node);
    super.visitForStatement(node);
  }

  @override
  void visitWhileStatement(WhileStatement node) {
    _checkLoop(node);
    super.visitWhileStatement(node);
  }

  @override
  void visitDoStatement(DoStatement node) {
    _checkLoop(node);
    super.visitDoStatement(node);
  }

  void _checkPersistenceContracts(ClassDeclaration node, String text) {
    final MethodDeclaration? copyWith = node.body.members
        .whereType<MethodDeclaration>()
        .where((MethodDeclaration method) => method.name.lexeme == 'copyWith')
        .firstOrNull;
    if (copyWith != null) {
      final Set<String> fields = node.body.members
          .whereType<FieldDeclaration>()
          .where(
            (FieldDeclaration declaration) =>
                !RegExp(r'^\s*static\b').hasMatch(declaration.toSource()),
          )
          .expand(
            (FieldDeclaration declaration) => declaration.fields.variables.map(
              (VariableDeclaration variable) => variable.name.lexeme,
            ),
          )
          .where((String name) => !name.startsWith('_'))
          .toSet();
      final Set<String> parameters =
          copyWith.parameters?.parameters
              .map((FormalParameter parameter) => parameter.name?.lexeme)
              .nonNulls
              .toSet() ??
          const <String>{};
      final _PreservedCopyFieldVisitor preserved = _PreservedCopyFieldVisitor(
        fields,
      );
      copyWith.body.accept(preserved);
      final Set<String> missing = fields.difference(<String>{
        ...parameters,
        ...preserved.fields,
      });
      if (fields.length > 1 && missing.isNotEmpty) {
        _add(
          copyWith,
          code: 'dart-copy-with-missing-field',
          message:
              'copyWith omits instance fields: ${missing.toList()..sort()}',
          why:
              'An incomplete copy operation can silently retain or discard state unexpectedly.',
          suggestion: 'Include every independently copyable field in copyWith.',
        );
      }
    }
    final MethodDeclaration? toJson = node.body.members
        .whereType<MethodDeclaration>()
        .where((MethodDeclaration method) => method.name.lexeme == 'toJson')
        .firstOrNull;
    final Set<String> enumNames = (node.root as CompilationUnit).declarations
        .whereType<EnumDeclaration>()
        .map(
          (EnumDeclaration declaration) => declaration.namePart.typeName.lexeme,
        )
        .toSet();
    final Set<String> enumFields = node.body.members
        .whereType<FieldDeclaration>()
        .where(
          (FieldDeclaration declaration) => enumNames.contains(
            declaration.fields.type?.toSource().replaceAll('?', ''),
          ),
        )
        .expand(
          (FieldDeclaration declaration) => declaration.fields.variables.map(
            (VariableDeclaration variable) => variable.name.lexeme,
          ),
        )
        .toSet();
    if (toJson != null &&
        enumFields.any(
          (String field) => RegExp(
            '''['"][^'"]+['"]\\s*:\\s*(?:this\\.)?${RegExp.escape(field)}\\.name\\b''',
          ).hasMatch(toJson.toSource()),
        )) {
      _add(
        toJson,
        code: 'dart-enum-name-persistence',
        message: 'enum name is used as a persisted representation',
        why:
            'Renaming an enum value changes stored data and external wire contracts.',
        suggestion:
            'Define an explicit stable wire value and parse it deliberately.',
      );
    }
    if (text.contains('toJson') && text.contains('fromJson')) {
      final Iterable<String> lateFinalFields = node.body.members
          .whereType<FieldDeclaration>()
          .where(
            (FieldDeclaration declaration) =>
                !declaration.isStatic &&
                declaration.fields.isLate &&
                declaration.fields.isFinal,
          )
          .expand(
            (FieldDeclaration declaration) => declaration.fields.variables.map(
              (VariableDeclaration variable) => variable.name.lexeme,
            ),
          );
      for (final String field in lateFinalFields) {
        if (RegExp(
          '\\b${RegExp.escape(field)}\\s*=\\s*(?:json|map|data)\\s*\\[',
        ).hasMatch(text)) {
          continue;
        }
        _add(
          node,
          code: 'dart-late-final-persistence',
          message:
              'persisted late final field `$field` is not restored explicitly',
          why:
              'A deserialized object can expose an uninitialized late field at runtime.',
          suggestion:
              'Initialize the field in every deserialization path or make it constructor-required.',
        );
      }
    }
  }

  void _checkSerialization(ClassDeclaration node) {
    final MethodDeclaration? toJson = node.body.members
        .whereType<MethodDeclaration>()
        .where((MethodDeclaration method) => method.name.lexeme == 'toJson')
        .firstOrNull;
    final AstNode? fromJson =
        node.body.members
            .whereType<ConstructorDeclaration>()
            .where(
              (ConstructorDeclaration constructor) =>
                  constructor.name?.lexeme == 'fromJson',
            )
            .firstOrNull ??
        node.body.members
            .whereType<MethodDeclaration>()
            .where(
              (MethodDeclaration method) => method.name.lexeme == 'fromJson',
            )
            .firstOrNull;
    if (toJson == null || fromJson == null) return;

    final Set<String> written = RegExp(r'''['"]([^'"]+)['"]\s*:''')
        .allMatches(toJson.toSource())
        .map((RegExpMatch match) => match.group(1)!)
        .toSet();
    final String decoder = fromJson.toSource();
    final Set<String> read = <String>{
      ...RegExp(
        r'''\b(?:json|map|data)\s*\[\s*['"]([^'"]+)['"]\s*\]''',
      ).allMatches(decoder).map((RegExpMatch match) => match.group(1)!),
      ...RegExp(
        r'''\b(?:reader\.\w+|required\w*)\s*\(\s*['"]([^'"]+)['"]''',
      ).allMatches(decoder).map((RegExpMatch match) => match.group(1)!),
    };
    if (written.isEmpty ||
        read.isEmpty ||
        written.containsAll(read) && read.containsAll(written)) {
      return;
    }
    final Set<String> onlyWritten = written.difference(read);
    final Set<String> onlyRead = read.difference(written);
    _add(
      node,
      code: 'dart-json-serialization-asymmetry',
      message:
          'toJson/fromJson fields differ: write-only=$onlyWritten read-only=$onlyRead',
      why:
          'Asymmetric serialization silently loses data or changes round trips.',
      suggestion:
          'Align the serialized and deserialized field sets or document intentional asymmetry.',
    );
  }

  void _checkLoop(AstNode node) {
    if (_hasLoopAncestor(node)) return;
    final String text = node.toSource();
    final AstNode? function = _enclosingFunction(node);
    if (function == null) return;
    final Set<String> stringVariables = RegExp(r'\bString\s+([A-Za-z_]\w*)')
        .allMatches(function.toSource())
        .map((RegExpMatch match) => match.group(1)!)
        .toSet();
    if (stringVariables.any(
      (String name) =>
          RegExp('\\b${RegExp.escape(name)}\\s*\\+=').hasMatch(text),
    )) {
      _add(
        node,
        code: 'dart-string-concat-in-loop',
        message: 'String concatenation occurs during each loop iteration',
        why:
            'Repeated immutable String concatenation can copy the growing prefix on every iteration.',
        suggestion: 'Accumulate with StringBuffer and call toString once.',
      );
    }
    final Set<String> listVariables =
        RegExp(r'\bList(?:<[^>]+>)?\s+([A-Za-z_]\w*)')
            .allMatches(function.toSource())
            .map((RegExpMatch match) => match.group(1)!)
            .toSet();
    if (listVariables.any(
      (String name) => RegExp(
        '\\b${RegExp.escape(name)}\\s*\\.\\s*contains\\s*\\(',
      ).hasMatch(text),
    )) {
      _add(
        node,
        code: 'dart-quadratic-list-membership',
        message:
            'List.contains performs a linear membership scan inside a loop',
        why:
            'Repeated list membership checks can turn a linear pass into quadratic work.',
        suggestion:
            'Build a Set once before the loop and use constant-time membership.',
      );
    }
  }

  void _checkRepeatedTraversal(MethodDeclaration node) {
    final _RepeatedTraversalVisitor traversal = _RepeatedTraversalVisitor(node);
    node.body.accept(traversal);
    for (final MapEntry<String, int> entry in traversal.counts.entries) {
      if (entry.value < 3) continue;
      _add(
        node,
        code: 'dart-repeated-iterable-traversal',
        message:
            '`${entry.key}` is traversed ${entry.value} times in one method',
        why:
            'Repeated linear scans multiply work and can dominate hot UI or data-processing paths.',
        suggestion: 'Fuse the predicates or build an indexed lookup once.',
      );
    }
  }

  bool _isFallbackProtectedDecoder(AstNode node) {
    AstNode? current = node.parent;
    while (current != null && current is! MethodDeclaration) {
      current = current.parent;
    }
    if (current is! MethodDeclaration) return false;
    final MethodDeclaration decoder = current;
    final String name = decoder.name.lexeme;
    if (!name.startsWith('_') ||
        !RegExp(r'(?:fromJson|decode)', caseSensitive: false).hasMatch(name)) {
      return false;
    }
    return _fallbackDecoderCache.putIfAbsent(name, () {
      AstNode root = decoder;
      AstNode? parent = root.parent;
      while (parent != null) {
        root = parent;
        parent = root.parent;
      }
      final _DecoderUseVisitor uses = _DecoderUseVisitor(
        name,
        decoder.name.offset,
        _isProtectedByFallback,
      );
      root.accept(uses);
      return uses.usages > 0 && uses.usages == uses.protectedUsages;
    });
  }

  bool _isProtectedByFallback(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is TryStatement &&
          node.offset >= current.body.offset &&
          node.end <= current.body.end &&
          current.catchClauses.any(
            (CatchClause clause) =>
                RegExp(r'\breturn\s+null\s*;').hasMatch(clause.body.toSource()),
          )) {
        return true;
      }
      if (current is FunctionBody) return false;
      current = current.parent;
    }
    return false;
  }

  bool _hasLoopAncestor(AstNode node) => _loopAncestor(node) != null;

  AstNode? _loopAncestor(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is ForStatement ||
          current is WhileStatement ||
          current is DoStatement) {
        return current;
      }
      if (current is FunctionBody) return null;
      current = current.parent;
    }
    return null;
  }

  AstNode? _repeatedLoopAncestor(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is ForStatement) {
        if (_containsNode(current.body, node)) return current;
        final ForLoopParts parts = current.forLoopParts;
        if (parts is ForParts) {
          final Expression? condition = parts.condition;
          if (condition != null && _containsNode(condition, node) ||
              parts.updaters.any(
                (Expression updater) => _containsNode(updater, node),
              )) {
            return current;
          }
        }
      } else if (current is WhileStatement || current is DoStatement) {
        return current;
      }
      if (current is FunctionBody) return null;
      current = current.parent;
    }
    return null;
  }

  bool _isInAsyncFunction(AstNode node) {
    final AstNode? function = _enclosingFunction(node);
    if (function is MethodDeclaration) return function.body.isAsynchronous;
    if (function is FunctionDeclaration) {
      return function.functionExpression.body.isAsynchronous;
    }
    if (function is FunctionExpression) return function.body.isAsynchronous;
    return false;
  }

  bool _isInsideEventCallback(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is FunctionExpression) {
        final int start = current.offset > 80 ? current.offset - 80 : 0;
        return RegExp(
          r'(?:on[A-Z]\w*|listener|callback)\s*:\s*$',
        ).hasMatch(source.substring(start, current.offset));
      }
      if (current is MethodDeclaration || current is FunctionDeclaration) {
        return false;
      }
      current = current.parent;
    }
    return false;
  }

  bool _isGuardedByTypeTest(AsExpression node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is FunctionDeclaration ||
          current is FunctionExpression ||
          current is MethodDeclaration) {
        return false;
      }
      if (current is ConditionalExpression) {
        if (_containsNode(current.thenExpression, node) &&
            _conditionGuaranteesType(
              current.condition,
              node.expression,
              node.type,
              whenTrue: true,
            )) {
          return true;
        }
        if (_containsNode(current.elseExpression, node) &&
            _conditionGuaranteesType(
              current.condition,
              node.expression,
              node.type,
              whenTrue: false,
            )) {
          return true;
        }
      }
      if (current is IfStatement) {
        if (_containsNode(current.thenStatement, node) &&
            _conditionGuaranteesType(
              current.expression,
              node.expression,
              node.type,
              whenTrue: true,
            )) {
          return true;
        }
        final Statement? elseStatement = current.elseStatement;
        if (elseStatement != null &&
            _containsNode(elseStatement, node) &&
            _conditionGuaranteesType(
              current.expression,
              node.expression,
              node.type,
              whenTrue: false,
            )) {
          return true;
        }
      }
      current = current.parent;
    }
    return false;
  }

  bool _conditionGuaranteesType(
    Expression condition,
    Expression operand,
    TypeAnnotation castType, {
    required bool whenTrue,
  }) {
    if (condition is ParenthesizedExpression) {
      return _conditionGuaranteesType(
        condition.expression,
        operand,
        castType,
        whenTrue: whenTrue,
      );
    }
    if (condition is PrefixExpression && condition.operator.lexeme == '!') {
      return _conditionGuaranteesType(
        condition.operand,
        operand,
        castType,
        whenTrue: !whenTrue,
      );
    }
    if (condition is IsExpression) {
      final bool positive = condition.notOperator == null;
      return whenTrue == positive &&
          _sameExpression(condition.expression, operand) &&
          _guardTypeAllowsCast(condition.type, castType);
    }
    if (condition is BinaryExpression) {
      final String operator = condition.operator.lexeme;
      final bool left = _conditionGuaranteesType(
        condition.leftOperand,
        operand,
        castType,
        whenTrue: whenTrue,
      );
      final bool right = _conditionGuaranteesType(
        condition.rightOperand,
        operand,
        castType,
        whenTrue: whenTrue,
      );
      if (operator == '&&') return whenTrue ? left || right : left && right;
      if (operator == '||') return whenTrue ? left && right : left || right;
    }
    return false;
  }

  bool _sameExpression(Expression left, Expression right) {
    final Expression normalizedLeft = left is ParenthesizedExpression
        ? left.expression
        : left;
    final Expression normalizedRight = right is ParenthesizedExpression
        ? right.expression
        : right;
    return normalizedLeft.toSource() == normalizedRight.toSource();
  }

  bool _guardTypeAllowsCast(TypeAnnotation guardType, TypeAnnotation castType) {
    final String guard = guardType.toSource();
    final String cast = castType.toSource();
    if (guard == cast) return true;
    if (guard.contains('<')) return false;
    final String rawCast = cast.split('<').first.replaceAll('?', '');
    return guard.replaceAll('?', '') == rawCast;
  }

  bool _unsafeSqlArgument(Argument argument) {
    if (argument is StringInterpolation) {
      return argument.elements.whereType<InterpolationExpression>().any(
        (InterpolationExpression element) =>
            !_isLiteralSqlConstant(element.expression, argument),
      );
    }
    return argument.toSource().contains(RegExp(r'''['"]\s*\+|\+\s*['"]'''));
  }

  bool _isLiteralSqlConstant(Expression expression, AstNode use) {
    if (expression is PrefixedIdentifier) {
      return _classLiteralSqlConstants[expression.prefix.name]?.contains(
            expression.identifier.name,
          ) ??
          false;
    }
    if (expression is! SimpleIdentifier ||
        _isShadowedByLocalDeclaration(expression.name, use)) {
      return false;
    }
    final String? className = _enclosingClassName(use);
    return (className != null &&
            (_classLiteralSqlConstants[className]?.contains(expression.name) ??
                false)) ||
        _topLevelLiteralSqlConstants.contains(expression.name);
  }

  bool _isShadowedByLocalDeclaration(String name, AstNode node) {
    if (_enclosingParameterNames(node).contains(name)) return true;
    final AstNode? function = _enclosingFunction(node);
    if (function == null) return false;
    final _VariableNameVisitor visitor = _VariableNameVisitor(name);
    function.accept(visitor);
    return visitor.found;
  }

  String? _enclosingClassName(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is ClassDeclaration) {
        return current.namePart.typeName.lexeme;
      }
      if (current is CompilationUnit) return null;
      current = current.parent;
    }
    return null;
  }

  bool _referencesPotentiallyUntrustedParameter(
    ArgumentList arguments,
    AstNode node,
    RegExp namePattern,
  ) {
    final Set<String> parameters = _enclosingParameterNames(
      node,
    ).where(namePattern.hasMatch).toSet();
    if (parameters.isEmpty) return false;
    final String text = arguments.toSource();
    return parameters.any(
      (String name) => RegExp('\\b${RegExp.escape(name)}\\b').hasMatch(text),
    );
  }

  Set<String> _enclosingParameterNames(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      FormalParameterList? list;
      if (current is MethodDeclaration) list = current.parameters;
      if (current is FunctionDeclaration) {
        list = current.functionExpression.parameters;
      }
      if (current is FunctionExpression) list = current.parameters;
      if (list != null) {
        return list.parameters
            .map((FormalParameter parameter) => parameter.name?.lexeme)
            .nonNulls
            .toSet();
      }
      current = current.parent;
    }
    return const <String>{};
  }

  bool _hasAwaitBefore(AstNode node) {
    final AstNode? function = _enclosingFunction(node);
    if (function == null) return false;
    final _AwaitBeforeVisitor visitor = _AwaitBeforeVisitor(node, function);
    function.accept(visitor);
    return visitor.found;
  }

  bool _hasMountedGuard(AstNode node) {
    final AstNode? function = _enclosingFunction(node);
    if (function == null) return false;
    final String prefix = source.substring(function.offset, node.offset);
    final int relativeAwaitOffset = prefix.lastIndexOf(RegExp(r'\bawait\b'));
    if (relativeAwaitOffset < 0) return false;

    AstNode? current = node;
    while (current != null && !identical(current, function)) {
      final AstNode? parent = current.parent;
      if (parent is IfStatement) {
        if (_containsNode(parent.thenStatement, node) &&
            _requiresMountedWhenTrue(parent.expression)) {
          return true;
        }
        final Statement? alternative = parent.elseStatement;
        if (alternative != null &&
            _containsNode(alternative, node) &&
            _requiresMountedWhenFalse(parent.expression)) {
          return true;
        }
      }
      if (parent is Block) {
        final int lastAwaitOffset = function.offset + relativeAwaitOffset;
        for (final Statement statement in parent.statements) {
          if (statement.offset >= current.offset) break;
          if (statement.offset > lastAwaitOffset &&
              statement is IfStatement &&
              _alwaysTerminates(statement.thenStatement) &&
              _requiresMountedWhenFalse(statement.expression)) {
            return true;
          }
        }
      }
      current = parent;
    }
    return false;
  }

  bool _requiresMountedWhenTrue(Expression expression) {
    if (expression is ParenthesizedExpression) {
      return _requiresMountedWhenTrue(expression.expression);
    }
    if (expression is BinaryExpression) {
      return switch (expression.operator.lexeme) {
        '&&' =>
          _requiresMountedWhenTrue(expression.leftOperand) ||
              _requiresMountedWhenTrue(expression.rightOperand),
        '||' =>
          _requiresMountedWhenTrue(expression.leftOperand) &&
              _requiresMountedWhenTrue(expression.rightOperand),
        _ => false,
      };
    }
    return RegExp(
      r'^(?:(?:this|context)\.)?mounted$',
    ).hasMatch(expression.toSource().trim());
  }

  bool _requiresMountedWhenFalse(Expression expression) {
    if (expression is ParenthesizedExpression) {
      return _requiresMountedWhenFalse(expression.expression);
    }
    if (expression is PrefixExpression && expression.operator.lexeme == '!') {
      return _requiresMountedWhenTrue(expression.operand);
    }
    if (expression is BinaryExpression) {
      return switch (expression.operator.lexeme) {
        '&&' =>
          _requiresMountedWhenFalse(expression.leftOperand) &&
              _requiresMountedWhenFalse(expression.rightOperand),
        '||' =>
          _requiresMountedWhenFalse(expression.leftOperand) ||
              _requiresMountedWhenFalse(expression.rightOperand),
        _ => false,
      };
    }
    return false;
  }

  bool _alwaysTerminates(Statement statement) =>
      statement is ReturnStatement ||
      (statement is Block &&
          statement.statements.isNotEmpty &&
          _alwaysTerminates(statement.statements.last));

  bool _containsNode(AstNode container, AstNode node) =>
      container.offset <= node.offset && node.end <= container.end;

  AstNode? _enclosingFunction(AstNode node) {
    AstNode? current = node.parent;
    while (current != null) {
      if (current is MethodDeclaration ||
          current is FunctionDeclaration ||
          current is FunctionExpression) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  void _add(
    AstNode node, {
    required String code,
    required String message,
    required String why,
    required String suggestion,
  }) {
    findings.add(
      _finding(
        code: code,
        path: path,
        line: _lineAt(node.offset),
        endLine: _lineAt(node.end),
        message: message,
        why: why,
        suggestion: suggestion,
      ),
    );
  }

  int _lineAt(int offset) =>
      '\n'.allMatches(source.substring(0, offset)).length + 1;

  static const Set<String> _sqlMethods = <String>{
    'execute',
    'query',
    'rawDelete',
    'rawInsert',
    'rawQuery',
    'rawUpdate',
  };
  static const Set<String> _syncFileMethods = <String>{
    'copySync',
    'createSync',
    'deleteSync',
    'existsSync',
    'listSync',
    'openSync',
    'readAsBytesSync',
    'readAsLinesSync',
    'readAsStringSync',
    'renameSync',
    'statSync',
    'writeAsBytesSync',
    'writeAsStringSync',
  };
  static const Set<String> _pathSinks = <String>{
    'join',
    'resolve',
    'open',
    'readAsString',
    'writeAsString',
  };
  static const Set<String> _loggingMethods = <String>{
    'debug',
    'error',
    'info',
    'log',
    'severe',
    'warning',
    'warn',
  };
  static final RegExp _commandInputName = RegExp(
    r'command|cmd|request|user|input',
    caseSensitive: false,
  );
  static final RegExp _pathInputName = RegExp(
    r'filename|fileName|relativePath|requestPath|upload|userPath|inputPath',
    caseSensitive: false,
  );
  static final RegExp _sensitiveName = RegExp(
    r'password|secret|api_?key|access_?token|auth_?token|authorization|cookie|private_?key',
    caseSensitive: false,
  );
}

final class _VariableNameVisitor extends RecursiveAstVisitor<void> {
  _VariableNameVisitor(this.name);

  final String name;
  bool found = false;

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    if (node.name.lexeme == name) found = true;
    if (!found) super.visitVariableDeclaration(node);
  }
}

final class _AwaitBeforeVisitor extends RecursiveAstVisitor<void> {
  _AwaitBeforeVisitor(this.target, this.function);

  final AstNode target;
  final AstNode function;
  bool found = false;

  @override
  void visitAwaitExpression(AwaitExpression node) {
    if (node.offset < target.offset && !_isMutuallyExclusive(node)) {
      found = true;
    }
    super.visitAwaitExpression(node);
  }

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    if (identical(node, function)) {
      super.visitFunctionDeclaration(node);
    }
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    if (identical(node, function) || identical(node.parent, function)) {
      super.visitFunctionExpression(node);
    }
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    if (identical(node, function)) {
      super.visitMethodDeclaration(node);
    }
  }

  bool _isMutuallyExclusive(AwaitExpression awaitExpression) {
    AstNode? current = awaitExpression.parent;
    while (current != null && !identical(current, function)) {
      if (current is IfStatement) {
        final Statement thenBranch = current.thenStatement;
        final Statement? elseBranch = current.elseStatement;
        if (elseBranch != null &&
            ((_contains(thenBranch, awaitExpression) &&
                    _contains(elseBranch, target)) ||
                (_contains(elseBranch, awaitExpression) &&
                    _contains(thenBranch, target)))) {
          return true;
        }
        if (target.offset >= current.end) {
          final Statement? awaitBranch = _contains(thenBranch, awaitExpression)
              ? thenBranch
              : elseBranch != null && _contains(elseBranch, awaitExpression)
              ? elseBranch
              : null;
          if (awaitBranch != null && _alwaysTerminates(awaitBranch)) {
            return true;
          }
        }
      }
      current = current.parent;
    }
    return false;
  }

  bool _alwaysTerminates(Statement statement) =>
      statement is ReturnStatement ||
      statement is ExpressionStatement &&
          statement.expression is ThrowExpression ||
      (statement is Block &&
          statement.statements.isNotEmpty &&
          _alwaysTerminates(statement.statements.last));

  bool _contains(AstNode container, AstNode node) =>
      container.offset <= node.offset && node.end <= container.end;
}

final class _SensitiveIdentifierVisitor extends RecursiveAstVisitor<void> {
  _SensitiveIdentifierVisitor(this.pattern);

  final RegExp pattern;
  bool found = false;

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (pattern.hasMatch(node.name)) {
      found = true;
    }
  }
}

final class _RepeatedTraversalVisitor extends RecursiveAstVisitor<void> {
  _RepeatedTraversalVisitor(MethodDeclaration method) {
    for (final FormalParameter parameter
        in method.parameters?.parameters ?? const <FormalParameter>[]) {
      final RegExpMatch? declaration = _collectionDeclaration.firstMatch(
        parameter.toSource(),
      );
      if (declaration != null) collectionNames.add(declaration.group(1)!);
    }
  }

  final Set<String> collectionNames = <String>{};
  final Map<String, int> counts = <String, int>{};

  @override
  void visitVariableDeclarationList(VariableDeclarationList node) {
    final String type = node.type?.toSource() ?? '';
    if (_collectionType.hasMatch(type)) {
      collectionNames.addAll(
        node.variables.map(
          (VariableDeclaration variable) => variable.name.lexeme,
        ),
      );
    }
    super.visitVariableDeclarationList(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String? receiver = node.target?.toSource();
    if (receiver != null &&
        collectionNames.contains(receiver) &&
        const <String>{
          'where',
          'firstWhere',
          'any',
          'contains',
        }.contains(node.methodName.name)) {
      counts[receiver] = (counts[receiver] ?? 0) + 1;
    }
    super.visitMethodInvocation(node);
  }

  static final RegExp _collectionType = RegExp(
    r'^(?:Iterable|List|Queue)(?:<|$)',
  );
  static final RegExp _collectionDeclaration = RegExp(
    r'(?:Iterable|List|Queue)(?:<[^>]+>)?\s+([A-Za-z_]\w*)',
  );
}

final class _DecoderUseVisitor extends RecursiveAstVisitor<void> {
  _DecoderUseVisitor(this.targetName, this.declarationOffset, this.isProtected);

  final String targetName;
  final int declarationOffset;
  final bool Function(AstNode node) isProtected;
  int usages = 0;
  int protectedUsages = 0;

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (node.name == targetName && node.offset != declarationOffset) {
      usages++;
      if (isProtected(node)) protectedUsages++;
    }
    super.visitSimpleIdentifier(node);
  }
}

Finding _finding({
  required String code,

  required String path,
  required int line,
  int? endLine,
  required String message,
  required String why,
  required String suggestion,
}) => Finding(
  code: code,
  severity: RuleSeverity.warn,
  path: path,
  line: line,
  endLine: endLine ?? line,
  message: message,
  confidence: 'high',
  why: why,
  suggestion: suggestion,
);
