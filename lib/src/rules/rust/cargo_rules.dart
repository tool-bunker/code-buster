// Cargo manifest rules enforce workspace-level dependency provenance that source-only Rust linters cannot inspect.

import 'package:toml/toml.dart';

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';

final class RustUnpinnedGitDependencyRule extends SelfContainedRule {
  RustUnpinnedGitDependencyRule()
    : super(
        const RuleMetadata(
          id: 'rust-unpinned-git-dependency',
          defaultSeverity: RuleSeverity.warn,
          group: 'security',
          title: 'Pin Rust Git dependencies to immutable revisions',
          why:
              'A branch or tag can move after review and silently change the dependency source selected by a future resolution.',
          suggestion:
              'Set rev to a full commit identifier or use a reviewed registry release with a committed lockfile.',
          version: 1,
          semanticMaturity: RuleSemanticMaturity.project,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.declarations,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.security},
          securityKind: SecurityFindingKind.hotspot,
          languages: <String>['rust'],
          limitations: <String>[
            'The rule verifies that a rev field exists but cannot establish upstream trust or repository integrity.',
            'Cargo source replacement and organization-specific trust policy are not resolved.',
          ],
        ),
      );

  static final RegExp _dependencyLine = cachedRegExp(
    r'^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^\n]*\bgit\s*=',
    multiLine: true,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry
        in context.auxiliaryFiles.entries) {
      if (!entry.key.endsWith('Cargo.toml') || entry.key.startsWith('@base/')) {
        continue;
      }
      final Map<String, Object?> manifest;
      try {
        manifest = Map<String, Object?>.from(
          TomlDocument.parse(entry.value).toMap(),
        );
      } on Object {
        continue;
      }
      final Set<String> unpinned = <String>{};
      _collectUnpinnedDependencies(manifest, unpinned);
      if (unpinned.isEmpty) continue;
      final Set<String> reported = <String>{};
      for (final RegExpMatch match in _dependencyLine.allMatches(entry.value)) {
        final String name = match.requiredGroup(1);
        if (!unpinned.contains(name) || !reported.add(name)) continue;
        yield report(
          context,
          path: entry.key,
          line:
              1 + '\n'.allMatches(entry.value.substring(0, match.start)).length,
          message: 'Git dependency $name is not pinned with an immutable rev',
          confidence: 'high',
        );
      }
    }
  }
}

void _collectUnpinnedDependencies(
  Map<String, Object?> table,
  Set<String> result,
) {
  for (final MapEntry<String, Object?> entry in table.entries) {
    final Object? value = entry.value;
    if (entry.key == 'dependencies' ||
        entry.key == 'dev-dependencies' ||
        entry.key == 'build-dependencies') {
      if (value is! Map<Object?, Object?>) continue;
      for (final MapEntry<Object?, Object?> dependency in value.entries) {
        if (dependency.key is! String ||
            dependency.value is! Map<Object?, Object?>) {
          continue;
        }
        final Map<Object?, Object?> specification =
            dependency.value! as Map<Object?, Object?>;
        if (specification['git'] is String &&
            !(specification['rev'] is String &&
                (specification['rev']! as String).trim().isNotEmpty)) {
          result.add(dependency.key! as String);
        }
      }
      continue;
    }
    if (value is Map<Object?, Object?>) {
      _collectUnpinnedDependencies(Map<String, Object?>.from(value), result);
    }
  }
}
