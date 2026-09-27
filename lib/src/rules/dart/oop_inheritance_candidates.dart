// Rejected inherited operations and dominant forwarding expose inheritance and delegation boundaries worth revisiting.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Dart advisories for inheritance and delegation boundaries.
const List<String> dartOopInheritanceCandidateRuleIds = <String>[
  'oop-refused-bequest',
  'oop-middle-man-delegation',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-inheritance-candidates');

/// Reports one independently configurable inheritance advisory.
final class DartOopInheritanceCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by one shared project-wide Dart AST scan.
  DartOopInheritanceCandidateRule(String id) : super(_metadata(id));

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
            relatedFiles: finding.relatedFiles,
          ),
        );
  }
}

RuleMetadata _metadata(String id) => oopRuleMetadata(id);

Map<String, List<Finding>> _analyze(Map<String, CompilationUnit> units) {
  final Map<String, List<_BaseClass>> basesByName =
      <String, List<_BaseClass>>{};
  final List<_Subclass> subclasses = <_Subclass>[];
  final List<Finding> middleMen = <Finding>[];

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String className = declaration.namePart.typeName.lexeme;
      final int line = entry.value.lineInfo
          .getLocation(declaration.offset)
          .lineNumber;
      final Set<String> methods = declaration.body.members
          .whereType<MethodDeclaration>()
          .where((MethodDeclaration method) => !method.isStatic)
          .map((MethodDeclaration method) => method.name.lexeme)
          .toSet();
      if (methods.length >= 4) {
        basesByName
            .putIfAbsent(className, () => <_BaseClass>[])
            .add(
              _BaseClass(
                name: className,
                path: entry.key,
                line: line,
                methods: methods,
              ),
            );
      }

      final String? parent = declaration.extendsClause?.superclass.toSource();
      if (parent != null) {
        final Set<String> rejected = <String>{};
        for (final MethodDeclaration method
            in declaration.body.members.whereType<MethodDeclaration>()) {
          if (method.metadata.any(
                (Annotation annotation) => annotation.toSource() == '@override',
              ) &&
              _throwsUnsupported(method)) {
            rejected.add(method.name.lexeme);
          }
        }
        if (rejected.isNotEmpty) {
          subclasses.add(
            _Subclass(
              parent: _baseType(parent),
              path: entry.key,
              rejectedMethods: rejected,
            ),
          );
        }
      }

      final Finding? middleMan = _middleManFinding(
        declaration,
        path: entry.key,
        line: line,
        className: className,
      );
      if (middleMan != null) middleMen.add(middleMan);
    }
  }

  return <String, List<Finding>>{
    'oop-refused-bequest': _refusedBequestFindings(basesByName, subclasses),
    'oop-middle-man-delegation': middleMen,
  };
}

List<Finding> _refusedBequestFindings(
  Map<String, List<_BaseClass>> basesByName,
  List<_Subclass> subclasses,
) {
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<_BaseClass>> entry in basesByName.entries) {
    if (entry.value.length != 1) continue;
    final _BaseClass base = entry.value.single;
    final List<_Subclass> rejecting = <_Subclass>[];
    for (final _Subclass subclass in subclasses) {
      if (subclass.parent != base.name) continue;
      final Set<String> inherited = subclass.rejectedMethods.intersection(
        base.methods,
      );
      if (inherited.length >= 2) {
        rejecting.add(
          _Subclass(
            parent: subclass.parent,
            path: subclass.path,
            rejectedMethods: inherited,
          ),
        );
      }
    }
    final Set<String> rejectedMethods = rejecting
        .expand((_Subclass subclass) => subclass.rejectedMethods)
        .toSet();
    if (rejecting.length < 2 || rejectedMethods.length < 3) continue;
    final Set<String> paths = rejecting
        .map((_Subclass subclass) => subclass.path)
        .toSet();
    findings.add(
      Finding(
        code: 'oop-refused-bequest',
        severity: RuleSeverity.info,
        path: base.path,
        line: base.line,
        message:
            '${base.name} has ${rejectedMethods.length} inherited operations rejected by ${rejecting.length} direct subclasses',
        confidence: 'high',
        relatedFiles: paths.where((String path) => path != base.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

Finding? _middleManFinding(
  ClassDeclaration declaration, {
  required String path,
  required int line,
  required String className,
}) {
  if (declaration.extendsClause != null ||
      declaration.implementsClause != null ||
      declaration.withClause != null) {
    return null;
  }
  final Set<String> privateFields = <String>{};
  for (final FieldDeclaration field
      in declaration.body.members.whereType<FieldDeclaration>()) {
    if (field.fields.type == null || field.isStatic) continue;
    for (final VariableDeclaration variable in field.fields.variables) {
      if (variable.name.lexeme.startsWith('_')) {
        privateFields.add(variable.name.lexeme);
      }
    }
  }
  if (privateFields.isEmpty) return null;

  final List<MethodDeclaration> publicMethods = declaration.body.members
      .whereType<MethodDeclaration>()
      .where(
        (MethodDeclaration method) =>
            !method.isStatic &&
            !method.isGetter &&
            !method.isSetter &&
            !method.isOperator &&
            !method.name.lexeme.startsWith('_'),
      )
      .toList();
  if (publicMethods.length < 5) return null;

  final Map<String, int> forwardingByField = <String, int>{};
  for (final MethodDeclaration method in publicMethods) {
    final MethodInvocation? invocation = _directInvocation(method.body);
    final String? target = invocation?.target?.toSource();
    if (invocation != null &&
        target != null &&
        privateFields.contains(target) &&
        invocation.methodName.name == method.name.lexeme &&
        _forwardsParameters(method, invocation)) {
      forwardingByField.update(
        target,
        (int count) => count + 1,
        ifAbsent: () => 1,
      );
    }
  }
  if (forwardingByField.isEmpty) return null;
  final MapEntry<String, int> dominant = forwardingByField.entries.reduce(
    (MapEntry<String, int> left, MapEntry<String, int> right) =>
        left.value >= right.value ? left : right,
  );
  if (dominant.value < 4 || dominant.value * 5 < publicMethods.length * 4) {
    return null;
  }
  return Finding(
    code: 'oop-middle-man-delegation',
    severity: RuleSeverity.info,
    path: path,
    line: line,
    message:
        '$className forwards ${dominant.value} of ${publicMethods.length} public methods unchanged to ${dominant.key}',
    confidence: 'high',
  );
}

MethodInvocation? _directInvocation(FunctionBody body) {
  Expression? expression;
  if (body is ExpressionFunctionBody) {
    expression = body.expression;
  } else if (body is BlockFunctionBody && body.block.statements.length == 1) {
    final Statement statement = body.block.statements.single;
    expression = switch (statement) {
      final ReturnStatement returned => returned.expression,
      final ExpressionStatement expressed => expressed.expression,
      _ => null,
    };
  }
  return expression is MethodInvocation ? expression : null;
}

bool _forwardsParameters(
  MethodDeclaration method,
  MethodInvocation invocation,
) {
  final FormalParameterList? parameters = method.parameters;
  if (parameters == null ||
      parameters.parameters.length !=
          invocation.argumentList.arguments.length) {
    return false;
  }
  for (var index = 0; index < parameters.parameters.length; index++) {
    final String? parameterName = parameters.parameters[index].name?.lexeme;
    if (parameterName == null) return false;
    final Argument argument = invocation.argumentList.arguments[index];
    if (argument is NamedArgument) {
      if (argument.name.lexeme != parameterName ||
          argument.argumentExpression.toSource() != parameterName) {
        return false;
      }
    } else if (argument.toSource() != parameterName) {
      return false;
    }
  }
  return true;
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

final class _BaseClass {
  const _BaseClass({
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

final class _Subclass {
  const _Subclass({
    required this.parent,
    required this.path,
    required this.rejectedMethods,
  });

  final String parent;
  final String path;
  final Set<String> rejectedMethods;
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
    // A nested callback does not reject its owning override.
  }
}
