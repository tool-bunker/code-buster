// Repeated object translation and near-identical sibling workflows are evidence for explicit boundary and workflow abstractions.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Dart advisories for duplicated object-boundary workflows.
const List<String> dartOopWorkflowCandidateRuleIds = <String>[
  'oop-repeated-adapter-mapping',
  'oop-template-workflow-candidate',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-workflow-candidates');

/// Reports one independently configurable workflow-design advisory.
final class DartOopWorkflowCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by one shared project-wide Dart AST scan.
  DartOopWorkflowCandidateRule(String id) : super(_metadata(id));

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit> units = context
        .requireLanguageAnalysis<Map<String, CompilationUnit>>();
    final Map<String, List<Finding>> findingsByCode =
        _findingsByUnits[units] ??= _analyze(units);
    return findingsByCode[metadata.id]!.map(
      (Finding finding) => context.report(
        metadata: metadata,
        path: finding.path,
        line: finding.line,
        message: finding.message,
        confidence: finding.confidence,
        relatedFiles: finding.relatedFiles,
      ),
    );
  }
}

RuleMetadata _metadata(String id) => oopRuleMetadata(id);

Map<String, List<Finding>> _analyze(Map<String, CompilationUnit> units) {
  final Map<String, List<_Occurrence>> mappings = <String, List<_Occurrence>>{};
  final List<_Workflow> workflows = <_Workflow>[];

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    final _MappingDeclarationVisitor mappingsVisitor =
        _MappingDeclarationVisitor(
          path: entry.key,
          lineAt: (int offset) =>
              entry.value.lineInfo.getLocation(offset).lineNumber,
          onMapping: (String key, _Occurrence occurrence) =>
              mappings.putIfAbsent(key, () => <_Occurrence>[]).add(occurrence),
        );
    entry.value.accept(mappingsVisitor);

    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String? parent = declaration.extendsClause?.superclass.toSource();
      if (parent == null) continue;
      for (final MethodDeclaration method
          in declaration.body.members.whereType<MethodDeclaration>()) {
        if (!method.metadata.any(
          (Annotation annotation) => annotation.toSource() == '@override',
        )) {
          continue;
        }
        final _OrderedInvocationVisitor calls = _OrderedInvocationVisitor();
        method.body.accept(calls);
        if (calls.names.length < 4 || calls.names.length > 10) continue;
        workflows.add(
          _Workflow(
            parent: _baseType(parent),
            className: declaration.namePart.typeName.lexeme,
            methodName: method.name.lexeme,
            path: entry.key,
            line: entry.value.lineInfo.getLocation(method.offset).lineNumber,
            calls: calls.names,
          ),
        );
      }
    }
  }

  return <String, List<Finding>>{
    'oop-repeated-adapter-mapping': _mappingFindings(mappings),
    'oop-template-workflow-candidate': _workflowFindings(workflows),
  };
}

List<Finding> _mappingFindings(Map<String, List<_Occurrence>> mappings) {
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<_Occurrence>> entry in mappings.entries) {
    final Set<String> paths = entry.value
        .map((_Occurrence occurrence) => occurrence.path)
        .toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    entry.value.sort(_compareOccurrences);
    final _Occurrence first = entry.value.first;
    final List<String> keyParts = entry.key.split('|');
    findings.add(
      Finding(
        code: 'oop-repeated-adapter-mapping',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            '${keyParts[0]} to ${keyParts[1]} mapping is repeated in ${entry.value.length} functions across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((String path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

List<Finding> _workflowFindings(List<_Workflow> workflows) {
  workflows.sort((_Workflow left, _Workflow right) {
    final int path = left.path.compareTo(right.path);
    return path != 0 ? path : left.line.compareTo(right.line);
  });
  final List<Finding> findings = <Finding>[];
  final Set<String> reportedPairs = <String>{};
  for (var leftIndex = 0; leftIndex < workflows.length; leftIndex++) {
    final _Workflow left = workflows[leftIndex];
    for (
      var rightIndex = leftIndex + 1;
      rightIndex < workflows.length;
      rightIndex++
    ) {
      final _Workflow right = workflows[rightIndex];
      if (left.path == right.path ||
          left.parent != right.parent ||
          left.methodName != right.methodName ||
          left.calls.length != right.calls.length) {
        continue;
      }
      final List<int> differences = <int>[
        for (var index = 0; index < left.calls.length; index++)
          if (left.calls[index] != right.calls[index]) index,
      ];
      if (differences.length != 1) continue;
      final String pair = (<String>[
        left.className,
        right.className,
      ]..sort()).join('|');
      if (!reportedPairs.add(pair)) continue;
      final int varyingIndex = differences.single;
      findings.add(
        Finding(
          code: 'oop-template-workflow-candidate',
          severity: RuleSeverity.info,
          path: left.path,
          line: left.line,
          message:
              '${left.className}.${left.methodName} and ${right.className}.${right.methodName} repeat ${left.calls.length - 1} calls and vary only ${left.calls[varyingIndex]} versus ${right.calls[varyingIndex]}',
          confidence: 'high',
          relatedFiles: <String>[right.path],
        ),
      );
    }
  }
  return findings;
}

int _compareOccurrences(_Occurrence left, _Occurrence right) {
  final int path = left.path.compareTo(right.path);
  return path != 0 ? path : left.line.compareTo(right.line);
}

String _baseType(String source) => source
    .replaceFirst(RegExp(r'<.*$'), '')
    .replaceFirst(RegExp(r'\?$'), '')
    .trim();

final class _Occurrence {
  const _Occurrence({required this.path, required this.line});

  final String path;
  final int line;
}

final class _Workflow {
  const _Workflow({
    required this.parent,
    required this.className,
    required this.methodName,
    required this.path,
    required this.line,
    required this.calls,
  });

  final String parent;
  final String className;
  final String methodName;
  final String path;
  final int line;
  final List<String> calls;
}

final class _MappingDeclarationVisitor extends RecursiveAstVisitor<void> {
  _MappingDeclarationVisitor({
    required this.path,
    required this.lineAt,
    required this.onMapping,
  });

  final String path;
  final int Function(int offset) lineAt;
  final void Function(String key, _Occurrence occurrence) onMapping;

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    _record(
      returnType: node.returnType?.toSource(),
      parameters: node.functionExpression.parameters,
      body: node.functionExpression.body,
      offset: node.offset,
    );
    super.visitFunctionDeclaration(node);
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    _record(
      returnType: node.returnType?.toSource(),
      parameters: node.parameters,
      body: node.body,
      offset: node.offset,
    );
    super.visitMethodDeclaration(node);
  }

  void _record({
    required String? returnType,
    required FormalParameterList? parameters,
    required FunctionBody body,
    required int offset,
  }) {
    if (returnType == null ||
        parameters == null ||
        parameters.parameters.length != 1) {
      return;
    }
    final FormalParameter parameter = parameters.parameters.single;
    final String? sourceName = parameter.name?.lexeme;
    if (sourceName == null) return;
    final String? sourceType = _explicitParameterType(parameter, sourceName);
    if (sourceType == null) return;
    final String targetType = _baseType(returnType);
    final _TargetMappingVisitor mappings = _TargetMappingVisitor(
      targetType: targetType,
      sourceName: sourceName,
    );
    body.accept(mappings);
    if (mappings.matches.length != 1) return;
    final List<String> fields = mappings.matches.single;
    if (fields.length < 3) return;
    fields.sort();
    onMapping(
      <String>[sourceType, targetType, ...fields].join('|'),
      _Occurrence(path: path, line: lineAt(offset)),
    );
  }
}

String? _explicitParameterType(FormalParameter parameter, String name) {
  final RegExpMatch? typed = RegExp(
    r'^\s*(?:required\s+)?(?:final\s+)?([A-Za-z_$][\w$]*(?:<[^>]+>)?\??)\s+' +
        RegExp.escape(name) +
        r'(?:\s*=.*)?\s*$',
    dotAll: true,
  ).firstMatch(parameter.toSource());
  return typed == null ? null : _baseType(typed.group(1)!);
}

final class _TargetMappingVisitor extends RecursiveAstVisitor<void> {
  _TargetMappingVisitor({required this.targetType, required this.sourceName});

  final String targetType;
  final String sourceName;
  final List<List<String>> matches = <List<String>>[];

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    if (_baseType(node.constructorName.type.toSource()) == targetType) {
      _record(node.argumentList);
    }
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (node.target == null && node.methodName.name == targetType) {
      _record(node.argumentList);
    }
    super.visitMethodInvocation(node);
  }

  void _record(ArgumentList arguments) {
    final List<String> fields = <String>[];
    for (final Argument argument in arguments.arguments) {
      if (argument is! NamedArgument) return;
      final RegExpMatch? sourceField = RegExp(
        '^${RegExp.escape(sourceName)}${r'\.([A-Za-z_$][\w$]*)$'}',
      ).firstMatch(argument.argumentExpression.toSource());
      if (sourceField == null) return;
      fields.add('${argument.name.lexeme}=${sourceField.group(1)}');
    }
    if (fields.isNotEmpty) matches.add(fields);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // A conversion created inside a callback is not the enclosing function's
    // direct mapping boundary.
  }
}

final class _OrderedInvocationVisitor extends RecursiveAstVisitor<void> {
  final List<String> names = <String>[];

  @override
  void visitMethodInvocation(MethodInvocation node) {
    names.add(node.methodName.name);
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks are separate workflows.
  }
}
