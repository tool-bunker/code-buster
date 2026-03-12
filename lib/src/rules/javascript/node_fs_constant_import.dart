// Node filesystem constants are properties of fs, not standalone modules; this rule catches imports that can never resolve as intended.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports Node file-access constants imported directly from `node:fs`.
final class JavaScriptNodeFsConstantImportRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const JavaScriptNodeFsConstantImportRule()
    : super(
        const RuleMetadata(
          id: 'js-node-fs-constant-import',
          defaultSeverity: RuleSeverity.error,
          group: 'core',
          title: 'Import file access modes through fs.constants',
          why:
              'Node does not export F_OK, R_OK, W_OK, or X_OK directly from node:fs.',
          suggestion:
              'Import constants from node:fs and reference constants.R_OK and related modes.',
          semanticMaturity: RuleSemanticMaturity.typeAware,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.imports,
            RuleAnalysisRequirement.types,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.correctness},
          languages: <String>['javascript', 'typescript'],
          languageVersions: <String, String>{'node': '>=12'},
          limitations: <String>[
            'Validation currently covers Node file-access constants from node:fs.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      for (final RegExpMatch declaration in _nodeFsImport.allMatches(
        source.value,
      )) {
        final List<String> invalid =
            declaration
                .group(1)!
                .split(',')
                .map(
                  (String item) => item.trim().split(RegExp(r'\s+as\s+')).first,
                )
                .where(_fileAccessConstants.contains)
                .toSet()
                .toList(growable: false)
              ..sort();
        if (invalid.isEmpty) continue;
        yield report(
          context,
          path: source.key,
          line:
              '\n'
                  .allMatches(source.value.substring(0, declaration.start))
                  .length +
              1,
          message:
              'Node file-access constants must use fs.constants: ${invalid.join(', ')}',
          confidence: 'high',
        );
      }
    }
  }

  static const Set<String> _fileAccessConstants = <String>{
    'F_OK',
    'R_OK',
    'W_OK',
    'X_OK',
  };
  static final RegExp _nodeFsImport = RegExp(
    r'''import\s*\{([^}]*)\}\s*from\s*["'](?:node:)?fs["']''',
    multiLine: true,
  );
}
