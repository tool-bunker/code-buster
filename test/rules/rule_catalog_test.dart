import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  group('RuleCatalog', () {
    test('indexes every currently emitted Dart rule with stable metadata', () {
      final List<String> ids = RuleCatalog.all
          .map((RuleMetadata rule) => rule.id)
          .toList(growable: false);
      expect(ids, orderedEquals(List<String>.of(ids)..sort()));
      expect(ids.toSet(), hasLength(ids.length));
      expect(
        ids,
        containsAll(<String>[
          'complex-function',
          'cpp-malloc-free',
          'cs-hardcoded-secret',
          'dart-process-shell',
          'html-img-alt',
          'css-important',
          'java-objectinputstream',
          'sql-delete-without-where',
        ]),
      );
      expect(RuleCatalog.lookup('dart-process-shell')!.group, 'security');
      final RuleMetadata nodeImport = RuleCatalog.lookup(
        'js-node-fs-constant-import',
      )!;
      expect(nodeImport.version, 1);
      expect(nodeImport.semanticMaturity, RuleSemanticMaturity.typeAware);
      expect(nodeImport.requirements, <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.imports,
        RuleAnalysisRequirement.types,
      });
      expect(nodeImport.effectiveTaxonomy, <FindingTaxonomy>{
        FindingTaxonomy.correctness,
      });
      expect(nodeImport.languages, <String>['javascript', 'typescript']);
      expect(nodeImport.languageVersions['node'], '>=12');
      expect(nodeImport.limitations, isNotEmpty);
      expect(
        RuleCatalog.lookup('cycle')!.semanticMaturity,
        RuleSemanticMaturity.project,
      );
      expect(
        RuleCatalog.lookup('go-shell-command')!.effectiveSecurityKind,
        SecurityFindingKind.hotspot,
      );
      expect(
        RuleCatalog.lookup('go-insecure-tls')!.effectiveSecurityKind,
        SecurityFindingKind.vulnerability,
      );
      expect(
        RuleCatalog.lookup('java-resource-not-closed')!.effectiveTaxonomy,
        <FindingTaxonomy>{FindingTaxonomy.reliability},
      );
      expect(RuleCatalog.lookup('no-such-rule'), isNull);
    });

    test('validates every built-in executable rule against metadata', () {
      final List<String> ids = RuleExecutionStage.standardRepositoryRules
          .map((CodeBusterRule rule) => rule.metadata.id)
          .toList(growable: false);

      expect(
        ids,
        orderedEquals(<String>[
          'tab-indent',
          'trailing-whitespace',
          'long-line',
          'todo-comment',
          'fixme-comment',
          'operation-on-same-value',
          'excessive-comment-density',
          'narrating-implementation-comment',
          'trivial-comment-restatement',
          'single-method-delegating-class',
          'parallel-schema-definition',
          'suspicious-command-arg-space',
          'large-number-ungrouped',
          'large-inline-list',
          'needless-bool-branch',
          'sql-inline-string-concat',
          'ai-prompt-injection-instruction',
          'ai-untrusted-prompt-construction',
          'ai-model-output-to-execution',
        ]),
      );
      expect(
        () => RuleCatalog.validateExecutableRules(const <CodeBusterRule>[
          _MissingMetadataRule(),
        ]),
        throwsStateError,
      );
      expect(
        () => RuleCatalog.validateExecutableRules(const <CodeBusterRule>[
          _CopiedMetadataRule(),
        ]),
        throwsStateError,
      );
    });
  });
}

final class _MissingMetadataRule implements CodeBusterRule {
  const _MissingMetadataRule();

  @override
  RuleMetadata get metadata => const RuleMetadata(
    id: 'missing-from-catalog',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'Missing metadata',
    why: 'Test fixture.',
    suggestion: 'Register metadata.',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) => const <Finding>[];
}

final class _CopiedMetadataRule implements CodeBusterRule {
  const _CopiedMetadataRule();

  @override
  RuleMetadata get metadata => const RuleMetadata(
    id: 'todo-comment',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'Copied metadata',
    why: 'Test fixture.',
    suggestion: 'Use the catalog object.',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) => const <Finding>[];
}
