// Java package boundaries can cycle independently of class-level details, so this rule analyzes the package dependency projection.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../graph/graph.dart';

/// Reports dependency cycles between Java packages.
final class JavaPackageCycleRule extends SelfContainedRule {
  /// Creates the stateless project rule.
  const JavaPackageCycleRule()
    : super(
        const RuleMetadata(
          id: 'java-package-cycle',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Break Java package dependency cycle',
          why:
              'Package cycles blur ownership and prevent one-way architecture boundaries.',
          suggestion:
              'Extract shared contracts or invert one package dependency.',
          semanticMaturity: RuleSemanticMaturity.project,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.imports,
            RuleAnalysisRequirement.graph,
          },
          languages: <String>['java'],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, ({String module, String package})> ownerByPath =
        <String, ({String module, String package})>{};
    final Map<String, Set<String>> nodesByPackage = <String, Set<String>>{};
    for (final MapEntry<String, String> source in context.sources.entries) {
      final String? packageName = _package.firstMatch(source.value)?.group(1);
      if (packageName == null) continue;
      final String module = _moduleFor(source.key);
      final String node = _packageNode(module, packageName);
      ownerByPath[source.key] = (module: module, package: packageName);
      nodesByPackage.putIfAbsent(packageName, () => <String>{}).add(node);
    }
    final Map<String, Set<String>> edges = <String, Set<String>>{
      for (final Set<String> nodes in nodesByPackage.values)
        for (final String node in nodes) node: <String>{},
    };
    for (final MapEntry<String, String> source in context.sources.entries) {
      final ({String module, String package})? owner = ownerByPath[source.key];
      if (owner == null) continue;
      final String ownerNode = _packageNode(owner.module, owner.package);
      for (final RegExpMatch match in _import.allMatches(source.value)) {
        final String imported = match.group(1)!;
        String? packageName;
        for (final String candidate in nodesByPackage.keys) {
          if ((imported == candidate || imported.startsWith('$candidate.')) &&
              (packageName == null || candidate.length > packageName.length)) {
            packageName = candidate;
          }
        }
        if (packageName == null || packageName == owner.package) continue;
        final Set<String> candidates = nodesByPackage[packageName]!;
        final String sameModule = _packageNode(owner.module, packageName);
        final String? target = candidates.contains(sameModule)
            ? sameModule
            : candidates.length == 1
            ? candidates.single
            : null;
        if (target != null && target != ownerNode) {
          edges[ownerNode]!.add(target);
        }
      }
    }
    return GraphAnalysis(DependencyGraph(edges)).cycleFindings().map(
      (Finding cycle) => report(
        context,
        path: _displayPackageNode(cycle.path),
        line: 1,
        message: cycle.message.replaceFirst(
          'circular dependency',
          'package cycle',
        ),
        confidence: 'high',
        relatedFiles: cycle.relatedFiles.map(_displayPackageNode).toList(),
      ),
    );
  }

  static String _moduleFor(String sourcePath) {
    const String marker = '/src/main/java/';
    final int markerIndex = sourcePath.indexOf(marker);
    if (markerIndex < 0) return '.';
    final String module = sourcePath.substring(0, markerIndex);
    return module.isEmpty ? '.' : module;
  }

  static String _packageNode(String module, String packageName) =>
      module == '.' ? packageName : '$module::$packageName';

  static String _displayPackageNode(String node) {
    final int separator = node.indexOf('::');
    if (separator < 0) return node.replaceAll('.', '/');
    final String module = node.substring(0, separator);
    final String packageName = node.substring(separator + 2);
    return '$module/src/main/java/${packageName.replaceAll('.', '/')}';
  }

  static final RegExp _package = RegExp(
    r'^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;',
    multiLine: true,
  );
  static final RegExp _import = RegExp(
    r'^\s*import\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_*]\w*)*)\s*;',
    multiLine: true,
  );
}
