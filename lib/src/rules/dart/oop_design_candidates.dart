// Repeated signatures and dispatch structures can expose missing domain abstractions without prescribing their implementation.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';

/// Independently configurable Dart OOP design advisories.
const List<String> dartOopDesignCandidateRuleIds = <String>[
  'oop-data-clump',
  'oop-repeated-strategy-dispatch',
];

final Expando<Map<String, List<Finding>>> _findingsByUnits =
    Expando<Map<String, List<Finding>>>('dart-oop-design-candidates');

/// Reports one conservative object-oriented design candidate.
final class DartOopDesignCandidateRule extends SelfContainedRule {
  /// Creates a rule backed by the shared Dart AST analysis.
  DartOopDesignCandidateRule(String id) : super(_metadata(id));

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
  'oop-data-clump' => const RuleMetadata(
    id: 'oop-data-clump',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Group a repeated parameter concept',
    why:
        'The same typed parameter group crossing several APIs usually represents one domain concept whose validation and evolution are otherwise distributed.',
    suggestion:
        'Consider a value object or parameter object if these values share invariants and lifecycle.',
    semanticMaturity: RuleSemanticMaturity.ast,
    requirements: <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.ast,
      RuleAnalysisRequirement.declarations,
    },
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart'],
    limitations: <String>[
      'Requires the same complete signature of at least three explicitly typed parameters in three declarations across at least two files.',
      'Parameter names and normalized types must match; inferred field formals and partial parameter subsets are not analyzed.',
    ],
  ),
  'oop-repeated-strategy-dispatch' => const RuleMetadata(
    id: 'oop-repeated-strategy-dispatch',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Consolidate repeated variant dispatch',
    why:
        'Repeating the same variant switch across operations makes every new variant require coordinated edits in several places.',
    suggestion:
        'Consider variant-owned behavior, a strategy registry, or another single dispatch boundary if the operations share one contract.',
    semanticMaturity: RuleSemanticMaturity.ast,
    requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.ast},
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart'],
    limitations: <String>[
      'Requires three switch statements across at least two files with the same three or more explicit case labels.',
      'Every case must invoke behavior and each case in a switch must dispatch to a distinct call name.',
      'Switch expressions, default-only dispatch, and differing case sets are not analyzed.',
    ],
  ),
  _ => throw ArgumentError.value(id, 'id', 'unknown Dart OOP design rule'),
};

Map<String, List<Finding>> _analyze(Map<String, CompilationUnit> units) {
  final Map<String, List<_Occurrence>> parameterGroups =
      <String, List<_Occurrence>>{};
  final Map<String, List<_Occurrence>> dispatchGroups =
      <String, List<_Occurrence>>{};

  for (final MapEntry<String, CompilationUnit> entry in units.entries) {
    final _DesignCandidateVisitor visitor = _DesignCandidateVisitor(
      path: entry.key,
      lineAt: (int offset) =>
          entry.value.lineInfo.getLocation(offset).lineNumber,
      onParameterGroup: (String key, _Occurrence occurrence) => parameterGroups
          .putIfAbsent(key, () => <_Occurrence>[])
          .add(occurrence),
      onDispatch: (String key, _Occurrence occurrence) => dispatchGroups
          .putIfAbsent(key, () => <_Occurrence>[])
          .add(occurrence),
    );
    entry.value.accept(visitor);
  }

  return <String, List<Finding>>{
    'oop-data-clump': _dataClumpFindings(parameterGroups),
    'oop-repeated-strategy-dispatch': _strategyFindings(dispatchGroups),
  };
}

List<Finding> _dataClumpFindings(
  Map<String, List<_Occurrence>> parameterGroups,
) {
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<_Occurrence>> entry
      in parameterGroups.entries) {
    final Set<String> paths = entry.value
        .map((_Occurrence occurrence) => occurrence.path)
        .toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    entry.value.sort(_compareOccurrences);
    final _Occurrence first = entry.value.first;
    final String names = entry.key
        .split('|')
        .map((String parameter) => parameter.split(' ').last)
        .join(', ');
    findings.add(
      Finding(
        code: 'oop-data-clump',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            'Parameters $names recur together in ${entry.value.length} declarations across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((String path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

List<Finding> _strategyFindings(Map<String, List<_Occurrence>> dispatchGroups) {
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<_Occurrence>> entry
      in dispatchGroups.entries) {
    final Set<String> paths = entry.value
        .map((_Occurrence occurrence) => occurrence.path)
        .toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    entry.value.sort(_compareOccurrences);
    final _Occurrence first = entry.value.first;
    findings.add(
      Finding(
        code: 'oop-repeated-strategy-dispatch',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            '${entry.value.length} switches repeat dispatch for ${entry.key.split('|').join(', ')} across ${paths.length} files',
        confidence: 'medium',
        relatedFiles: paths.where((String path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

int _compareOccurrences(_Occurrence left, _Occurrence right) {
  final int path = left.path.compareTo(right.path);
  return path != 0 ? path : left.line.compareTo(right.line);
}

final class _Occurrence {
  const _Occurrence({required this.path, required this.line});

  final String path;
  final int line;
}

final class _DesignCandidateVisitor extends RecursiveAstVisitor<void> {
  _DesignCandidateVisitor({
    required this.path,
    required this.lineAt,
    required this.onParameterGroup,
    required this.onDispatch,
  });

  final String path;
  final int Function(int offset) lineAt;
  final void Function(String key, _Occurrence occurrence) onParameterGroup;
  final void Function(String key, _Occurrence occurrence) onDispatch;

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    _recordParameters(node.functionExpression.parameters, node.offset);
    super.visitFunctionDeclaration(node);
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    _recordParameters(node.parameters, node.offset);
    super.visitMethodDeclaration(node);
  }

  @override
  void visitConstructorDeclaration(ConstructorDeclaration node) {
    _recordParameters(node.parameters, node.offset);
    super.visitConstructorDeclaration(node);
  }

  @override
  void visitSwitchStatement(SwitchStatement node) {
    final List<String> labels = <String>[];
    final List<Set<String>> callsByCase = <Set<String>>[];
    for (final SwitchMember member in node.members) {
      final RegExpMatch? label = RegExp(
        r'^\s*case\s+(.+?)(?:\s+when\s+.+)?:',
        dotAll: true,
      ).firstMatch(member.toSource());
      if (label == null) continue;
      final _InvocationNameVisitor calls = _InvocationNameVisitor();
      member.accept(calls);
      if (calls.names.isEmpty) {
        labels.clear();
        break;
      }
      labels.add(label.group(1)!.replaceAll(RegExp(r'\s+'), ' ').trim());
      callsByCase.add(calls.names);
    }
    if (labels.length >= 3 && _hasDistinctDispatchCalls(callsByCase)) {
      labels.sort();
      onDispatch(
        labels.join('|'),
        _Occurrence(path: path, line: lineAt(node.offset)),
      );
    }
    super.visitSwitchStatement(node);
  }

  static bool _hasDistinctDispatchCalls(List<Set<String>> callsByCase) {
    final Map<String, int> ownerByCall = <String, int>{};
    bool assign(int caseIndex, Set<String> visited) {
      for (final String call in callsByCase[caseIndex]) {
        if (!visited.add(call)) continue;
        final int? owner = ownerByCall[call];
        if (owner == null || assign(owner, visited)) {
          ownerByCall[call] = caseIndex;
          return true;
        }
      }
      return false;
    }

    for (var index = 0; index < callsByCase.length; index++) {
      if (!assign(index, <String>{})) return false;
    }
    return true;
  }

  void _recordParameters(FormalParameterList? list, int offset) {
    if (list == null || list.parameters.length < 3) return;
    final List<String> parameters = <String>[];
    for (final FormalParameter parameter in list.parameters) {
      final String? name = parameter.name?.lexeme;
      if (name == null) return;
      final String source = parameter.toSource();
      final RegExpMatch? typed = RegExp(
        r'^\s*(?:required\s+)?(?:final\s+)?([A-Za-z_$][\w$]*(?:<[^>]+>)?\??)\s+(?:this\.)?' +
            RegExp.escape(name) +
            r'(?:\s*=.*)?\s*$',
        dotAll: true,
      ).firstMatch(source);
      if (typed == null) return;
      parameters.add('${typed.group(1)} $name');
    }
    parameters.sort();
    onParameterGroup(
      parameters.join('|'),
      _Occurrence(path: path, line: lineAt(offset)),
    );
  }
}

final class _InvocationNameVisitor extends RecursiveAstVisitor<void> {
  final Set<String> names = <String>{};

  @override
  void visitMethodInvocation(MethodInvocation node) {
    names.add(node.methodName.name);
    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    names.add(node.constructorName.type.toSource());
    super.visitInstanceCreationExpression(node);
  }
}
