// Unsupported interface members and distributed lifecycle switches are conservative evidence of strained object contracts.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Dart advisories for object contracts under structural pressure.
const List<String> dartOopContractCandidateRuleIds = <String>[
  'oop-interface-segregation-pressure',
  'oop-state-behavior-candidate',
  'oop-single-use-abstraction',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-contract-candidates');

/// Reports one independently configurable contract-design advisory.
final class DartOopContractCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by the shared project-wide AST analysis.
  DartOopContractCandidateRule(String id) : super(_metadata(id));

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

RuleMetadata _metadata(String id) => switch (id) {
  'oop-interface-segregation-pressure' => oopRuleMetadata(id),
  'oop-state-behavior-candidate' => oopRuleMetadata(id),
  'oop-single-use-abstraction' => oopRuleMetadata(id),
  _ => throw ArgumentError.value(id, 'id', 'unknown Dart OOP contract rule'),
};

Map<String, List<Finding>> _analyze(Map<String, CompilationUnit> units) {
  final Map<String, List<_Contract>> contracts = <String, List<_Contract>>{};
  final List<_Implementation> implementations = <_Implementation>[];
  final List<Finding> stateFindings = <Finding>[];

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String className = declaration.namePart.typeName.lexeme;
      final Set<String> abstractMethods = declaration.body.members
          .whereType<MethodDeclaration>()
          .where((MethodDeclaration method) => method.body is EmptyFunctionBody)
          .map((MethodDeclaration method) => method.name.lexeme)
          .toSet();
      if (abstractMethods.length >= 4) {
        contracts
            .putIfAbsent(className, () => <_Contract>[])
            .add(
              _Contract(
                name: className,
                path: entry.key,
                line: entry.value.lineInfo
                    .getLocation(declaration.offset)
                    .lineNumber,
                methods: abstractMethods,
              ),
            );
      }

      final List<NamedType> interfaces =
          declaration.implementsClause?.interfaces ?? const <NamedType>[];
      for (final NamedType interface in interfaces) {
        implementations.add(
          _Implementation(
            interfaceName: _baseType(interface.toSource()),
            path: entry.key,
            unsupportedMethods: declaration.body.members
                .whereType<MethodDeclaration>()
                .where(_throwsUnsupported)
                .map((MethodDeclaration method) => method.name.lexeme)
                .toSet(),
          ),
        );
      }

      final Finding? stateFinding = _stateFinding(
        declaration,
        entry.key,
        entry.value,
      );
      if (stateFinding != null) stateFindings.add(stateFinding);
    }
  }

  final List<Finding> interfaceFindings = <Finding>[];
  for (final List<_Contract> namedContracts in contracts.values) {
    if (namedContracts.length != 1) continue;
    final _Contract contract = namedContracts.single;
    final List<_Implementation> implementors = implementations
        .where(
          (_Implementation implementation) =>
              implementation.interfaceName == contract.name,
        )
        .toList();
    if (implementors.length < 2) continue;
    final List<_Implementation> rejecting = implementors
        .map(
          (_Implementation implementation) =>
              implementation.onlyContractMethods(contract.methods),
        )
        .where(
          (_Implementation implementation) =>
              implementation.unsupportedMethods.isNotEmpty,
        )
        .toList();
    final int rejectedImplementations = rejecting.fold(
      0,
      (int total, _Implementation implementation) =>
          total + implementation.unsupportedMethods.length,
    );
    final Set<String> rejectedMethods = rejecting
        .expand(
          (_Implementation implementation) => implementation.unsupportedMethods,
        )
        .toSet();
    if (rejecting.length < 2 ||
        rejectedImplementations < 3 ||
        rejectedMethods.length < 2) {
      continue;
    }
    final Set<String> related = rejecting
        .map((_Implementation implementation) => implementation.path)
        .where((String path) => path != contract.path)
        .toSet();
    interfaceFindings.add(
      Finding(
        code: 'oop-interface-segregation-pressure',
        severity: RuleSeverity.info,
        path: contract.path,
        line: contract.line,
        message:
            '${contract.name} has ${contract.methods.length} operations; ${rejecting.length} implementors contain $rejectedImplementations rejected implementations across ${rejectedMethods.length} operations',
        confidence: 'high',
        relatedFiles: related.toList()..sort(),
      ),
    );
  }

  return <String, List<Finding>>{
    'oop-interface-segregation-pressure': interfaceFindings,
    'oop-state-behavior-candidate': stateFindings,
    'oop-single-use-abstraction': _singleUseFindings(units),
  };
}

List<Finding> _singleUseFindings(Map<String, CompilationUnit> units) {
  final List<
    ({String path, CompilationUnit unit, ClassDeclaration declaration})
  >
  classes =
      <({String path, CompilationUnit unit, ClassDeclaration declaration})>[];
  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      classes.add((
        path: entry.key,
        unit: entry.value,
        declaration: declaration,
      ));
    }
  }

  final List<Finding> findings = <Finding>[];
  for (final contract in classes) {
    final List<MethodDeclaration> contractMethods = contract
        .declaration
        .body
        .members
        .whereType<MethodDeclaration>()
        .toList(growable: false);
    if (contractMethods.length != 1 ||
        contractMethods.single.body is! EmptyFunctionBody ||
        contract.declaration.body.members
            .whereType<FieldDeclaration>()
            .isNotEmpty) {
      continue;
    }
    final String contractName = contract.declaration.namePart.typeName.lexeme;
    final List<
      ({String path, CompilationUnit unit, ClassDeclaration declaration})
    >
    implementors = classes
        .where((candidate) {
          final ClassDeclaration declaration = candidate.declaration;
          final List<NamedType> interfaces =
              declaration.implementsClause?.interfaces ?? const <NamedType>[];
          return interfaces.length == 1 &&
              _baseType(interfaces.single.toSource()) == contractName &&
              declaration.extendsClause == null &&
              declaration.withClause == null;
        })
        .toList(growable: false);
    if (implementors.length != 1) continue;

    final implementation = implementors.single;
    final List<MethodDeclaration> methods = implementation
        .declaration
        .body
        .members
        .whereType<MethodDeclaration>()
        .where((method) => !method.isStatic)
        .toList(growable: false);
    if (methods.length != 1 ||
        methods.single.name.lexeme != contractMethods.single.name.lexeme ||
        implementation.declaration.body.members
            .whereType<FieldDeclaration>()
            .isNotEmpty ||
        !_isSmallDartBehavior(methods.single)) {
      continue;
    }

    final _TypeEvidenceVisitor evidence = _TypeEvidenceVisitor(
      contractName,
      implementation.declaration.namePart.typeName.lexeme,
    );
    for (final CompilationUnit unit in units.values) {
      unit.accept(evidence);
    }
    if (evidence.contractReferences > 2 ||
        evidence.implementationConstructions != 1) {
      continue;
    }
    findings.add(
      Finding(
        code: 'oop-single-use-abstraction',
        severity: RuleSeverity.info,
        path: contract.path,
        line: contract.unit.lineInfo
            .getLocation(contract.declaration.offset)
            .lineNumber,
        message:
            '$contractName has one stateless implementation, ${implementation.declaration.namePart.typeName.lexeme}, constructed once for one small operation',
        confidence: 'medium',
        relatedFiles: <String>[
          if (implementation.path != contract.path) implementation.path,
        ],
      ),
    );
  }
  return findings;
}

bool _isSmallDartBehavior(MethodDeclaration method) {
  final String source = method.body.toSource();
  if (source.length > 180) return false;
  final _ComplexBehaviorVisitor visitor = _ComplexBehaviorVisitor();
  method.body.accept(visitor);
  return !visitor.complex;
}

final class _TypeEvidenceVisitor extends RecursiveAstVisitor<void> {
  _TypeEvidenceVisitor(this.contractName, this.implementationName);

  final String contractName;
  final String implementationName;
  int contractReferences = 0;
  int implementationConstructions = 0;

  @override
  void visitNamedType(NamedType node) {
    if (_baseType(node.toSource()) == contractName) contractReferences++;
    super.visitNamedType(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    if (_baseType(node.constructorName.type.toSource()) == implementationName) {
      implementationConstructions++;
    }
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (node.target == null && node.methodName.name == implementationName) {
      implementationConstructions++;
    }
    super.visitMethodInvocation(node);
  }
}

final class _ComplexBehaviorVisitor extends RecursiveAstVisitor<void> {
  bool complex = false;

  @override
  void visitAwaitExpression(AwaitExpression node) => complex = true;

  @override
  void visitForStatement(ForStatement node) => complex = true;

  @override
  void visitIfStatement(IfStatement node) => complex = true;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) =>
      complex = true;

  @override
  void visitSwitchStatement(SwitchStatement node) => complex = true;

  @override
  void visitTryStatement(TryStatement node) => complex = true;

  @override
  void visitWhileStatement(WhileStatement node) => complex = true;
}

Finding? _stateFinding(
  ClassDeclaration declaration,
  String path,
  CompilationUnit unit,
) {
  for (final FieldDeclaration field
      in declaration.body.members.whereType<FieldDeclaration>()) {
    if (field.isStatic || field.fields.isFinal || field.fields.isConst) {
      continue;
    }
    final String type = _baseType(field.fields.type?.toSource() ?? '');
    if (!const <String>['State', 'Status', 'Phase'].any(type.endsWith)) {
      continue;
    }
    for (final VariableDeclaration variable in field.fields.variables) {
      final String fieldName = variable.name.lexeme;
      final _StateAssignmentVisitor assignments = _StateAssignmentVisitor(
        fieldName,
      );
      declaration.accept(assignments);
      if (!assignments.assigned) continue;

      final Map<String, Set<String>> methodsByCases = <String, Set<String>>{};
      for (final MethodDeclaration method
          in declaration.body.members.whereType<MethodDeclaration>()) {
        final _StateSwitchVisitor switches = _StateSwitchVisitor(fieldName);
        method.accept(switches);
        for (final String cases in switches.caseSets) {
          methodsByCases
              .putIfAbsent(cases, () => <String>{})
              .add(method.name.lexeme);
        }
      }
      for (final MapEntry<String, Set<String>> entry
          in methodsByCases.entries) {
        if (entry.value.length < 3) continue;
        return Finding(
          code: 'oop-state-behavior-candidate',
          severity: RuleSeverity.info,
          path: path,
          line: unit.lineInfo.getLocation(declaration.offset).lineNumber,
          message:
              '${declaration.namePart.typeName.lexeme} switches on mutable $fieldName across ${entry.value.length} methods for ${entry.key.split('|').join(', ')}',
          confidence: 'medium',
        );
      }
    }
  }
  return null;
}

bool _throwsUnsupported(MethodDeclaration method) {
  final _UnsupportedThrowVisitor visitor = _UnsupportedThrowVisitor();
  method.body.accept(visitor);
  return visitor.found;
}

String _baseType(String source) => source
    .replaceFirst(RegExp(r'<.*$'), '')
    .replaceFirst(RegExp(r'\?$'), '')
    .trim();

final class _Contract {
  const _Contract({
    required this.name,
    required this.path,
    required this.line,
    required this.methods,
  });

  final String name;
  final String path;
  final int line;
  final Set<String> methods;
}

final class _Implementation {
  const _Implementation({
    required this.interfaceName,
    required this.path,
    required this.unsupportedMethods,
  });

  final String interfaceName;
  final String path;
  final Set<String> unsupportedMethods;

  _Implementation onlyContractMethods(Set<String> contractMethods) =>
      _Implementation(
        interfaceName: interfaceName,
        path: path,
        unsupportedMethods: unsupportedMethods.intersection(contractMethods),
      );
}

final class _UnsupportedThrowVisitor extends RecursiveAstVisitor<void> {
  bool found = false;

  @override
  void visitThrowExpression(ThrowExpression node) {
    final String expression = node.expression.toSource();
    if (expression.startsWith('UnsupportedError(') ||
        expression.startsWith('UnimplementedError(')) {
      found = true;
    }
    super.visitThrowExpression(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // A nested callback rejecting an operation does not make its owning
    // interface method unsupported.
  }
}

final class _StateAssignmentVisitor extends RecursiveAstVisitor<void> {
  _StateAssignmentVisitor(this.fieldName);

  final String fieldName;
  bool assigned = false;

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final String target = node.leftHandSide.toSource();
    if (target == fieldName || target == 'this.$fieldName') assigned = true;
    super.visitAssignmentExpression(node);
  }
}

final class _StateSwitchVisitor extends RecursiveAstVisitor<void> {
  _StateSwitchVisitor(this.fieldName);

  final String fieldName;
  final Set<String> caseSets = <String>{};

  @override
  void visitSwitchStatement(SwitchStatement node) {
    final String expression = node.expression.toSource();
    if (expression != fieldName && expression != 'this.$fieldName') {
      super.visitSwitchStatement(node);
      return;
    }
    final List<String> labels = <String>[];
    for (final SwitchMember member in node.members) {
      final RegExpMatch? label = RegExp(
        r'^\s*case\s+(.+?)(?:\s+when\s+.+)?:',
        dotAll: true,
      ).firstMatch(member.toSource());
      if (label == null) continue;
      labels.add(label.group(1)!.replaceAll(RegExp(r'\s+'), ' ').trim());
    }
    if (labels.length >= 3) {
      labels.sort();
      caseSets.add(labels.join('|'));
    }
    super.visitSwitchStatement(node);
  }
}
