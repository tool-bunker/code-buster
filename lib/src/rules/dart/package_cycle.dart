// Package imports can form cycles even when individual files look harmless, so this rule evaluates the collapsed package graph.

import 'package:analyzer/dart/ast/ast.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../graph/graph.dart';
import '../../languages/dart/dart_adapter.dart';

/// Reports dependency cycles between Dart packages in a monorepo.
final class DartPackageCycleRule extends SelfContainedRule {
  /// Creates the project-wide cycle rule.
  const DartPackageCycleRule()
    : super(
        const RuleMetadata(
          id: 'dart-package-cycle',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Break Dart package dependency cycles',
          why:
              'Mutually dependent packages cannot be versioned or reused independently.',
          suggestion:
              'Move shared contracts into a lower-level package or invert one dependency.',
          semanticMaturity: RuleSemanticMaturity.project,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.imports,
            RuleAnalysisRequirement.graph,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.architecture},
          languages: <String>['dart'],
          limitations: <String>[
            'Package ownership is inferred from packages/* and the nearest lib directory.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit>? units =
        context.languageAnalysis is Map<String, CompilationUnit>
        ? context.languageAnalysis! as Map<String, CompilationUnit>
        : null;
    final Set<String> owners = context.sources.keys
        .where((String source) => source.endsWith('.dart'))
        .map(_owner)
        .where((String owner) => owner.isNotEmpty)
        .toSet();
    if (owners.length < 2) return const <Finding>[];
    final Map<String, Set<String>> edges = <String, Set<String>>{
      for (final String owner in owners) owner: <String>{},
    };
    final DartSourceParser parser = DartSourceParser();
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.dart')) continue;
      final String owner = _owner(source.key);
      final DartUnit unit = parser.summarize(
        units?[source.key] ??
            parser.parseCompilationUnit(source.value, sourcePath: source.key),
      );
      for (final String uri in <String>[...unit.imports, ...unit.exports]) {
        final RegExpMatch? imported = _packageImport.firstMatch(uri);
        if (imported == null) continue;
        final String target = imported.group(1)!;
        if (target != owner && owners.contains(target)) {
          edges[owner]!.add(target);
        }
      }
    }
    return GraphAnalysis(DependencyGraph(edges)).cycles().map(
      (List<String> cycle) => context.report(
        metadata: metadata,
        path: cycle.first,
        line: 1,
        message: 'Dart package cycle: ${cycle.join(' -> ')}',
        confidence: 'high',
        relatedFiles: cycle
            .skip(1)
            .take(cycle.length - 2)
            .toList(growable: false),
      ),
    );
  }

  static String _owner(String sourcePath) {
    final List<String> segments = sourcePath.replaceAll('\\', '/').split('/');
    final int packages = segments.indexOf('packages');
    if (packages >= 0 && packages + 1 < segments.length) {
      return segments[packages + 1];
    }
    final int lib = segments.lastIndexOf('lib');
    return lib > 0 ? segments[lib - 1] : 'root';
  }

  static final RegExp _packageImport = RegExp(r'^package:([^/]+)/');
}
