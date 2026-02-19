import 'package:code_buster/code_buster.dart';
import 'package:test/test.dart';

void main() {
  test('stable API supports third-party rules and language plugins', () {
    const CodeBusterRule rule = _PublicRule();
    final RuleRegistry rules = RuleRegistry(<CodeBusterRule>[rule]);
    final LanguagePluginRegistry languages = LanguagePluginRegistry(
      const <LanguagePlugin>[_PublicPlugin()],
    );

    expect(rules['public-rule'], same(rule));
    expect(languages.require('public').id, 'public');
    expect(rule.metadata.semanticMaturity, RuleSemanticMaturity.token);
    expect(rule.metadata.effectiveTaxonomy, <FindingTaxonomy>{
      FindingTaxonomy.correctness,
    });
    expect(ReportFormat.parse('sarif'), ReportFormat.sarif);
  });
}

final class _PublicRule implements CodeBusterRule {
  const _PublicRule();

  @override
  RuleMetadata get metadata => const RuleMetadata(
    id: 'public-rule',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'Public rule',
    why: 'Exercises the stable API.',
    suggestion: 'No action required.',
    semanticMaturity: RuleSemanticMaturity.token,
    requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.tokens},
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.correctness},
    securityKind: SecurityFindingKind.none,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) => const <Finding>[];
}

final class _PublicPlugin implements LanguagePlugin {
  const _PublicPlugin();

  @override
  String get id => 'public';

  @override
  Set<String> get sourceLanguageIds => const <String>{'public'};

  @override
  LanguageAnalysis analyze(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => LanguageAnalysis(
    graph: buildGraph(sources, config),
    functions: functions(sources),
    findings: const <Finding>[],
  );

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => DependencyGraph(const <String, Iterable<String>>{});

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}
