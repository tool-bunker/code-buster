// Established object-oriented boundaries should remain the dominant path into the implementation they own.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';

/// Supported abstraction roles, inferred only from conventional class suffixes.
enum OopAbstractionRole {
  factory('factory', 'Factory'),
  facade('facade', 'Facade'),
  repository('repository', 'Repository'),
  proxy('proxy', 'Proxy');

  const OopAbstractionRole(this.id, this.suffix);

  final String id;
  final String suffix;
}

/// Rule IDs registered by the Dart OOP abstraction analysis.
const List<String> dartOopAbstractionBypassRuleIds = <String>[
  'oop-factory-bypass',
  'oop-facade-bypass',
  'oop-repository-bypass',
  'oop-proxy-bypass',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-abstraction-bypass');

/// Reports direct implementation access that bypasses a dominant abstraction.
final class DartOopAbstractionBypassRule extends SelfContainedRule {
  /// Creates one independently configurable role rule.
  DartOopAbstractionBypassRule(String id) : super(_metadata(id));

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit> units = context
        .requireLanguageAnalysis<Map<String, CompilationUnit>>();
    final Map<String, List<Finding>> findingsByCode =
        _findingsByUnits[units] ??= _analyzeAbstractionBypasses(units);
    return findingsByCode[metadata.id]!.map(
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

Map<String, List<Finding>> _analyzeAbstractionBypasses(
  Map<String, CompilationUnit> units,
) {
  final Map<String, List<Finding>> result = <String, List<Finding>>{
    for (final String id in dartOopAbstractionBypassRuleIds) id: <Finding>[],
  };
  final List<_Abstraction> abstractions = <_Abstraction>[];
  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    for (final ClassDeclaration declaration
        in entry.value.declarations.whereType<ClassDeclaration>()) {
      final String name = declaration.namePart.typeName.lexeme;
      for (final OopAbstractionRole role in OopAbstractionRole.values) {
        if (!name.endsWith(role.suffix)) continue;
        final Set<String> covered = _coveredTypes(declaration, role);
        final int minimumCovered = role == OopAbstractionRole.facade ? 3 : 1;
        if (covered.length >= minimumCovered) {
          abstractions.add(
            _Abstraction(
              name: name,
              path: entry.key,
              role: role,
              coveredTypes: covered,
            ),
          );
        }
      }
    }
  }

  for (final _Abstraction abstraction in abstractions) {
    final Map<String, _ExternalUsage> usages = <String, _ExternalUsage>{};
    for (final MapEntry<String, CompilationUnit> entry in units.entries) {
      if (entry.key == abstraction.path) continue;
      final _AbstractionUsageVisitor visitor = _AbstractionUsageVisitor(
        abstraction,
      );
      entry.value.accept(visitor);
      usages[entry.key] = visitor.usage;
    }
    final int abstractionFiles = usages.values
        .where((_ExternalUsage usage) => usage.usesAbstraction)
        .length;
    final List<MapEntry<String, _ExternalUsage>> bypasses = usages.entries
        .where((MapEntry<String, _ExternalUsage> entry) => entry.value.isBypass)
        .toList();
    if (abstractionFiles < 3 || abstractionFiles <= bypasses.length) continue;

    final String code = 'oop-${abstraction.role.id}-bypass';
    for (final MapEntry<String, _ExternalUsage> bypass in bypasses) {
      final List<String> directTypes = bypass.value.directTypes.toList()
        ..sort();
      result[code]!.add(
        Finding(
          code: code,
          severity: RuleSeverity.info,
          path: bypass.key,
          line: units[bypass.key]!.lineInfo
              .getLocation(bypass.value.firstBypassOffset!)
              .lineNumber,
          message:
              '${bypass.key} accesses ${directTypes.join(', ')} directly although ${abstraction.name} is used by $abstractionFiles external files and is the dominant ${abstraction.role.id} boundary',
          confidence: 'high',
        ),
      );
    }
  }
  return result;
}

Set<String> _coveredTypes(
  ClassDeclaration declaration,
  OopAbstractionRole role,
) {
  if (role == OopAbstractionRole.factory) {
    final _CreatedTypeVisitor visitor = _CreatedTypeVisitor();
    declaration.accept(visitor);
    return visitor.types..remove(declaration.namePart.typeName.lexeme);
  }

  final Set<String> fieldTypes = <String>{};
  for (final FieldDeclaration field
      in declaration.body.members.whereType<FieldDeclaration>()) {
    if (field.isStatic) continue;
    final String? type = field.fields.type?.toSource();
    if (type == null) continue;
    final String normalized = _baseType(type);
    if (!_ignoredTypes.contains(normalized)) fieldTypes.add(normalized);
  }
  if (role == OopAbstractionRole.repository) {
    return fieldTypes
        .where(
          (String type) => const <String>[
            'Client',
            'Dao',
            'Database',
            'DataSource',
            'Store',
          ].any(type.endsWith),
        )
        .toSet();
  }
  return fieldTypes;
}

String _baseType(String source) => source
    .replaceFirst(RegExp(r'<.*$'), '')
    .replaceFirst(RegExp(r'\?$'), '')
    .trim();

const Set<String> _ignoredTypes = <String>{
  'bool',
  'double',
  'dynamic',
  'int',
  'num',
  'Object',
  'String',
};

final class _Abstraction {
  const _Abstraction({
    required this.name,
    required this.path,
    required this.role,
    required this.coveredTypes,
  });

  final String name;
  final String path;
  final OopAbstractionRole role;
  final Set<String> coveredTypes;
}

final class _ExternalUsage {
  _ExternalUsage(this.minimumDirectTypes);

  final int minimumDirectTypes;
  bool usesAbstraction = false;
  final Set<String> directTypes = <String>{};
  int? firstBypassOffset;

  bool get isBypass => directTypes.length >= minimumDirectTypes;
}

final class _CreatedTypeVisitor extends RecursiveAstVisitor<void> {
  final Set<String> types = <String>{};

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    types.add(_baseType(node.constructorName.type.toSource()));
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (node.target == null) types.add(node.methodName.name);
    super.visitMethodInvocation(node);
  }
}

final class _AbstractionUsageVisitor extends RecursiveAstVisitor<void> {
  _AbstractionUsageVisitor(this.abstraction)
    : usage = _ExternalUsage(
        abstraction.role == OopAbstractionRole.facade ? 2 : 1,
      );

  final _Abstraction abstraction;
  final _ExternalUsage usage;

  @override
  void visitNamedType(NamedType node) {
    final String type = _baseType(node.toSource());
    if (type == abstraction.name) usage.usesAbstraction = true;
    if (abstraction.role != OopAbstractionRole.factory) {
      _recordDirectType(type, node.offset);
    }
    super.visitNamedType(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final String type = _baseType(node.constructorName.type.toSource());
    if (type == abstraction.name) usage.usesAbstraction = true;
    _recordDirectType(type, node.offset);
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String? target = node.target?.toSource();
    if (target == abstraction.name ||
        (target == null && node.methodName.name == abstraction.name)) {
      usage.usesAbstraction = true;
    }
    if (target == null) {
      _recordDirectType(node.methodName.name, node.offset);
    }
    super.visitMethodInvocation(node);
  }

  void _recordDirectType(String type, int offset) {
    if (!abstraction.coveredTypes.contains(type)) return;
    usage.directTypes.add(type);
    usage.firstBypassOffset ??= offset;
  }
}
