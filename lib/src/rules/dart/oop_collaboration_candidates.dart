// Repeated observer broadcasts and long collaboration chains expose boundaries that can be made explicit.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Dart advisories for collaboration boundaries.
const List<String> dartOopCollaborationCandidateRuleIds = <String>[
  'oop-repeated-observer-notification',
  'oop-message-chain',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-collaboration-candidates');

/// Reports one independently configurable collaboration advisory.
final class DartOopCollaborationCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by one shared project-wide Dart AST scan.
  DartOopCollaborationCandidateRule(String id) : super(_metadata(id));

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit> units = context
        .requireLanguageAnalysis<Map<String, CompilationUnit>>();
    final Map<String, List<Finding>> findingsByCode =
        _findingsByUnits[units] ??= _analyze(units);
    return findingsByCode
        .requiredValue(metadata.id)
        .map(
          (Finding finding) => context.report(
            metadata: metadata,
            path: finding.path,
            line: finding.line,
            message: finding.message,
            confidence: finding.confidence,
          ),
        );
  }
}

RuleMetadata _metadata(String id) => oopRuleMetadata(id);

Map<String, List<Finding>> _analyze(Map<String, CompilationUnit> units) {
  final List<Finding> notifications = <Finding>[];
  final List<Finding> chains = <Finding>[];

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String? superclass = declaration.extendsClause?.superclass
          .toSource();
      if (superclass != null &&
          superclass.split('<').first.endsWith('AstVisitor')) {
        continue;
      }
      final String className = declaration.namePart.typeName.lexeme;
      if (className.endsWith('Analysis') || className.endsWith('RulePack')) {
        continue;
      }
      final int classLine = entry.value.lineInfo
          .getLocation(declaration.offset)
          .lineNumber;
      final Set<String> observerFields = _observerFields(declaration);
      if (observerFields.isNotEmpty) {
        final _RegistrationVisitor registrations = _RegistrationVisitor(
          observerFields,
        );
        declaration.body.accept(registrations);
        final Map<String, Map<String, Set<String>>> callbacksByField =
            <String, Map<String, Set<String>>>{};
        for (final MethodDeclaration method
            in declaration.body.members.whereType<MethodDeclaration>()) {
          final _NotificationLoopVisitor loops = _NotificationLoopVisitor(
            observerFields,
          );
          method.body.accept(loops);
          for (final _NotificationLoop loop in loops.loops) {
            callbacksByField
                .putIfAbsent(loop.field, () => <String, Set<String>>{})
                .putIfAbsent(loop.callback, () => <String>{})
                .add(method.name.lexeme);
          }
        }
        for (final MapEntry<String, Map<String, Set<String>>> fieldEntry
            in callbacksByField.entries) {
          final Set<String> operations =
              registrations.operations[fieldEntry.key] ?? const <String>{};
          if (!operations.containsAll(<String>{'add', 'remove'})) continue;
          for (final MapEntry<String, Set<String>> callbackEntry
              in fieldEntry.value.entries) {
            if (callbackEntry.value.length < 3) continue;
            notifications.add(
              Finding(
                code: 'oop-repeated-observer-notification',
                severity: RuleSeverity.info,
                path: entry.key,
                line: classLine,
                message:
                    '$className repeats ${fieldEntry.key} traversal calling ${callbackEntry.key} from ${callbackEntry.value.length} methods',
                confidence: 'high',
              ),
            );
          }
        }
      }

      var chainCount = 0;
      var methodsWithChains = 0;
      var maximumDepth = 0;
      for (final MethodDeclaration method
          in declaration.body.members.whereType<MethodDeclaration>()) {
        final _MessageChainVisitor visitor = _MessageChainVisitor();
        method.body.accept(visitor);
        if (visitor.depths.isEmpty) continue;
        methodsWithChains++;
        chainCount += visitor.depths.length;
        for (final int depth in visitor.depths) {
          if (depth > maximumDepth) maximumDepth = depth;
        }
      }
      if (chainCount >= 3 && methodsWithChains >= 2) {
        chains.add(
          Finding(
            code: 'oop-message-chain',
            severity: RuleSeverity.info,
            path: entry.key,
            line: classLine,
            message:
                '$className contains $chainCount collaboration chains of at least four hops across $methodsWithChains methods (maximum $maximumDepth)',
            confidence: 'high',
          ),
        );
      }
    }
  }

  return <String, List<Finding>>{
    'oop-repeated-observer-notification': notifications,
    'oop-message-chain': chains,
  };
}

Set<String> _observerFields(ClassDeclaration declaration) {
  final Set<String> fields = <String>{};
  for (final FieldDeclaration member
      in declaration.body.members.whereType<FieldDeclaration>()) {
    final String? type = member.fields.type?.toSource();
    if (type == null ||
        !(type.startsWith('List<') || type.startsWith('Set<'))) {
      continue;
    }
    for (final VariableDeclaration variable in member.fields.variables) {
      final String normalized = variable.name.lexeme
          .replaceAll('_', '')
          .toLowerCase();
      if (normalized == 'listeners' || normalized == 'observers') {
        fields.add(variable.name.lexeme);
      }
    }
  }
  return fields;
}

final class _RegistrationVisitor extends RecursiveAstVisitor<void> {
  _RegistrationVisitor(this.fields);

  final Set<String> fields;
  final Map<String, Set<String>> operations = <String, Set<String>>{};

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String? target = node.target?.toSource();
    final String operation = node.methodName.name;
    if (target != null &&
        fields.contains(target) &&
        (operation == 'add' || operation == 'remove')) {
      operations.putIfAbsent(target, () => <String>{}).add(operation);
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Registration hidden in a callback is not a direct class boundary.
  }
}

final class _NotificationLoop {
  const _NotificationLoop({required this.field, required this.callback});

  final String field;
  final String callback;
}

final class _NotificationLoopVisitor extends RecursiveAstVisitor<void> {
  _NotificationLoopVisitor(this.fields);

  final Set<String> fields;
  final List<_NotificationLoop> loops = <_NotificationLoop>[];

  @override
  void visitForStatement(ForStatement node) {
    for (final String field in fields) {
      final RegExpMatch? parts = RegExp(
        r'(?:^|\s)([A-Za-z_$][\w$]*)\s+in\s+' + RegExp.escape(field) + r'\s*$',
      ).firstMatch(node.forLoopParts.toSource());
      if (parts == null) continue;
      final _LoopCallVisitor calls = _LoopCallVisitor(parts.requiredGroup(1));
      node.body.accept(calls);
      if (calls.totalCalls == 1 && calls.calls.length == 1) {
        loops.add(
          _NotificationLoop(field: field, callback: calls.calls.single),
        );
      }
    }
    super.visitForStatement(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks own their notification loops.
  }
}

final class _LoopCallVisitor extends RecursiveAstVisitor<void> {
  _LoopCallVisitor(this.variable);

  final String variable;
  final List<String> calls = <String>[];
  var totalCalls = 0;

  @override
  void visitMethodInvocation(MethodInvocation node) {
    totalCalls++;
    if (node.target?.toSource() == variable) calls.add(node.methodName.name);
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks are not part of the loop's direct delivery.
  }
}

final class _MessageChainVisitor extends RecursiveAstVisitor<void> {
  final List<int> depths = <int>[];

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (!_continuesInParent(node)) _record(node);
    super.visitMethodInvocation(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    if (!_continuesInParent(node)) _record(node);
    super.visitPropertyAccess(node);
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    if (!_continuesInParent(node)) _record(node);
    super.visitPrefixedIdentifier(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks own their collaboration chains.
  }

  void _record(Expression expression) {
    final int depth = _chainDepth(expression);
    if (depth >= 4) depths.add(depth);
  }
}

bool _continuesInParent(Expression node) {
  final AstNode? parent = node.parent;
  return switch (parent) {
    final MethodInvocation invocation => identical(invocation.target, node),
    final PropertyAccess access => identical(access.realTarget, node),
    final IndexExpression index => identical(index.target, node),
    _ => false,
  };
}

int _chainDepth(Expression expression) => switch (expression) {
  final MethodInvocation invocation => switch (invocation.target) {
    final Expression target => _chainDepth(target) + 1,
    null => 0,
  },
  final PropertyAccess access => _chainDepth(access.realTarget) + 1,
  PrefixedIdentifier _ => 1,
  final IndexExpression index => switch (index.target) {
    final Expression target => _chainDepth(target) + 1,
    null => 0,
  },
  _ => 0,
};
