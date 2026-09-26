// Strong foreign-object use and distributed service lookup are evidence that responsibility or dependency ownership can move.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Dart advisories for responsibility and dependency ownership.
const List<String> dartOopOwnershipCandidateRuleIds = <String>[
  'oop-feature-envy',
  'oop-service-locator-dependency',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-ownership-candidates');

/// Reports one independently configurable ownership advisory.
final class DartOopOwnershipCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by one shared project-wide Dart AST scan.
  DartOopOwnershipCandidateRule(String id) : super(_metadata(id));

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
  final List<Finding> featureEnvy = <Finding>[];
  final Map<String, List<_LocatorUse>> locatorUses =
      <String, List<_LocatorUse>>{};

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String className = declaration.namePart.typeName.lexeme;
      final _LocatorVisitor locator = _LocatorVisitor();
      declaration.body.accept(locator);
      for (final MapEntry<String, Set<String>> use
          in locator.services.entries) {
        locatorUses
            .putIfAbsent(use.key, () => <_LocatorUse>[])
            .add(
              _LocatorUse(
                path: entry.key,
                line: entry.value.lineInfo
                    .getLocation(declaration.offset)
                    .lineNumber,
                className: className,
                services: use.value,
              ),
            );
      }

      for (final MethodDeclaration method
          in declaration.body.members.whereType<MethodDeclaration>()) {
        if (method.isStatic || method.parameters == null) continue;
        final List<_TypedParameter> parameters = <_TypedParameter>[
          for (final FormalParameter parameter in method.parameters!.parameters)
            if (_typedParameter(parameter) case final _TypedParameter typed)
              typed,
        ];
        parameters.removeWhere(
          (_TypedParameter parameter) =>
              _sameDeclaredType(parameter.type, className),
        );
        if (parameters.isEmpty) continue;
        final _MemberAccessVisitor accesses = _MemberAccessVisitor(
          parameters.map((_TypedParameter parameter) => parameter.name).toSet(),
        );
        method.body.accept(accesses);
        _TypedParameter? best;
        var bestCount = 0;
        for (final _TypedParameter parameter in parameters) {
          final List<String> members =
              accesses.foreignMembers[parameter.name] ?? const <String>[];
          if (members.length >= 5 &&
              members.toSet().length >= 3 &&
              members.length * 5 >= accesses.receivedAccessCount * 3 &&
              members.length > bestCount) {
            best = parameter;
            bestCount = members.length;
          }
        }
        if (best == null) continue;
        if (_isFlutterWidgetComposition(entry.value, method, best, bestCount)) {
          continue;
        }
        final Set<String> distinct = accesses.foreignMembers[best.name]!
            .toSet();
        featureEnvy.add(
          Finding(
            code: 'oop-feature-envy',
            severity: RuleSeverity.info,
            path: entry.key,
            line: entry.value.lineInfo.getLocation(method.offset).lineNumber,
            message:
                '$className.${method.name.lexeme} accesses ${best.type} parameter ${best.name} $bestCount times across ${distinct.length} members',
            confidence: 'high',
          ),
        );
      }
    }
  }

  return <String, List<Finding>>{
    'oop-feature-envy': featureEnvy,
    'oop-service-locator-dependency': _locatorFindings(locatorUses),
  };
}

List<Finding> _locatorFindings(Map<String, List<_LocatorUse>> usesByLocator) {
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<_LocatorUse>> entry
      in usesByLocator.entries) {
    final Set<String> classes = entry.value
        .map((_LocatorUse use) => '${use.path}:${use.className}')
        .toSet();
    final Set<String> paths = entry.value
        .map((_LocatorUse use) => use.path)
        .toSet();
    final Set<String> services = entry.value
        .expand((_LocatorUse use) => use.services)
        .toSet();
    if (classes.length < 3 || paths.length < 2 || services.length < 3) continue;
    entry.value.sort((_LocatorUse left, _LocatorUse right) {
      final int path = left.path.compareTo(right.path);
      return path != 0 ? path : left.line.compareTo(right.line);
    });
    final _LocatorUse first = entry.value.first;
    findings.add(
      Finding(
        code: 'oop-service-locator-dependency',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            '${entry.key} resolves ${services.length} service types from ${classes.length} classes across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((String path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

final class _TypedParameter {
  const _TypedParameter({required this.name, required this.type});

  final String name;
  final String type;
}

_TypedParameter? _typedParameter(FormalParameter parameter) {
  final String? name = parameter.name?.lexeme;
  if (name == null) return null;
  final RegExpMatch? typed = RegExp(
    r'^\s*(?:required\s+)?(?:final\s+)?([A-Za-z_$][\w$]*(?:<[^>]+>)?\??)\s+' +
        RegExp.escape(name) +
        r'(?:\s*=.*)?\s*$',
    dotAll: true,
  ).firstMatch(parameter.toSource());
  if (typed == null) return null;
  return _TypedParameter(name: name, type: typed.group(1)!);
}

bool _sameDeclaredType(String type, String className) {
  final String withoutNullability = type.endsWith('?')
      ? type.substring(0, type.length - 1)
      : type;
  final int typeArguments = withoutNullability.indexOf('<');
  return (typeArguments < 0
          ? withoutNullability
          : withoutNullability.substring(0, typeArguments)) ==
      className;
}

bool _isFlutterWidgetComposition(
  CompilationUnit unit,
  MethodDeclaration method,
  _TypedParameter parameter,
  int totalAccessCount,
) {
  if (method.returnType?.toSource() != 'Widget' ||
      !unit.directives.whereType<ImportDirective>().any(
        (ImportDirective directive) =>
            directive.uri.stringValue?.startsWith('package:flutter/') ?? false,
      )) {
    return false;
  }
  final _ReturnedMemberAccessVisitor returned = _ReturnedMemberAccessVisitor(
    <String>{parameter.name},
  );
  method.body.accept(returned);
  return (returned.accesses.foreignMembers[parameter.name]?.length ?? 0) ==
      totalAccessCount;
}

final class _MemberAccessVisitor extends RecursiveAstVisitor<void> {
  _MemberAccessVisitor(this.parameterNames);

  final Set<String> parameterNames;
  final Map<String, List<String>> foreignMembers = <String, List<String>>{};
  var receivedAccessCount = 0;

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final Expression? target = node.target;
    if (target != null) {
      receivedAccessCount++;
      _record(target.toSource(), node.methodName.name);
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    final Expression target = node.realTarget;
    receivedAccessCount++;
    _record(target.toSource(), node.propertyName.name);
    super.visitPropertyAccess(node);
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    receivedAccessCount++;
    _record(node.prefix.name, node.identifier.name);
    super.visitPrefixedIdentifier(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks own their accesses.
  }

  void _record(String receiver, String member) {
    if (!parameterNames.contains(receiver)) return;
    foreignMembers.putIfAbsent(receiver, () => <String>[]).add(member);
  }
}

final class _ReturnedMemberAccessVisitor extends RecursiveAstVisitor<void> {
  _ReturnedMemberAccessVisitor(Set<String> parameterNames)
    : accesses = _MemberAccessVisitor(parameterNames);

  final _MemberAccessVisitor accesses;

  @override
  void visitExpressionFunctionBody(ExpressionFunctionBody node) {
    node.expression.accept(accesses);
  }

  @override
  void visitReturnStatement(ReturnStatement node) {
    node.expression?.accept(accesses);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // A callback's return value does not compose the enclosing Widget.
  }
}

final class _LocatorUse {
  const _LocatorUse({
    required this.path,
    required this.line,
    required this.className,
    required this.services,
  });

  final String path;
  final int line;
  final String className;
  final Set<String> services;
}

final class _LocatorVisitor extends RecursiveAstVisitor<void> {
  final Map<String, Set<String>> services = <String, Set<String>>{};

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final TypeArgumentList? typeArguments = node.typeArguments;
    if (typeArguments == null || typeArguments.arguments.length != 1) {
      super.visitMethodInvocation(node);
      return;
    }
    final String method = node.methodName.name;
    final String? target = node.target?.toSource();
    String? locator;
    if (target == null && _isLocatorName(method)) {
      locator = method;
    } else if (method == 'get' && target != null && _isLocatorName(target)) {
      locator = target;
    }
    if (locator != null) {
      services
          .putIfAbsent(locator, () => <String>{})
          .add(typeArguments.arguments.single.toSource());
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    // Nested callbacks can execute under a different dependency boundary.
  }
}

bool _isLocatorName(String name) {
  final String normalized = name.replaceAll('_', '').toLowerCase();
  return normalized == 'getit' ||
      normalized == 'locator' ||
      normalized == 'servicelocator';
}
