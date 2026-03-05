import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/language_rules.dart';
import 'package:code_buster/src/rules/repository_rules.dart';
import 'package:test/test.dart';

void main() {
  test('every built-in language has one local rule manifest', () {
    final Set<String> pluginIds = LanguagePluginRegistry.standard().plugins
        .map((LanguagePlugin plugin) => plugin.id)
        .toSet();

    expect(languageRuleRegistries.keys.toSet(), pluginIds);
  });

  test('catalog metadata is derived from executable manifests', () {
    final Iterable<CodeBusterRule> executableRules = <CodeBusterRule>[
      ...repositoryRuleRegistry.rules,
      for (final RuleRegistry registry in languageRuleRegistries.values)
        ...registry.rules,
    ];

    for (final CodeBusterRule rule in executableRules) {
      expect(RuleCatalog.lookup(rule.metadata.id), same(rule.metadata));
    }
  });

  test('language plugins execute local rules automatically', () {
    const Map<String, String> sources = <String, String>{
      'Files.java': '''class Files {
  void leaking() {
    FileInputStream input = new FileInputStream(path);
  }
}
''',
    };
    final LanguageAnalysis analysis = LanguagePluginRegistry.standard()
        .require('java')
        .analyze(sources, const AnalysisConfig(root: '.'));

    expect(
      analysis.findings.map((Finding finding) => finding.code),
      contains('java-resource-not-closed'),
    );
  });

  test('language manifests honor group and explicit rule enablement', () {
    const Map<String, String> sources = <String, String>{
      'main.go': 'cfg := tls.Config{InsecureSkipVerify: true}',
    };
    final LanguagePlugin plugin = LanguagePluginRegistry.standard().require(
      'go',
    );

    final LanguageAnalysis disabled = plugin.analyze(
      sources,
      const AnalysisConfig(root: '.', ruleGroups: <String>{}),
    );
    final LanguageAnalysis enabled = plugin.analyze(
      sources,
      const AnalysisConfig(
        root: '.',
        ruleGroups: <String>{},
        severityOverrides: <String, RuleSeverity>{
          'go-insecure-tls': RuleSeverity.error,
        },
      ),
    );

    expect(disabled.findings, isEmpty);
    expect(enabled.findings.map((Finding finding) => finding.code), <String>[
      'go-insecure-tls',
    ]);
  });

  test('declarative patterns ignore comments and strings by default', () {
    final SourcePatternRule rule = SourcePatternRule(
      metadata: const RuleMetadata(
        id: 'sample-call',
        defaultSeverity: RuleSeverity.info,
        group: 'core',
        title: 'Sample call',
        why: 'Tests safe source matching.',
        suggestion: 'Remove the call.',
        languages: <String>['dart'],
      ),
      pattern: RegExp(r'\brisky\('),
      message: 'risky call',
    );
    final List<Finding> findings = rule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.dart': '''// risky()
final text = "risky()";
risky();
''',
            },
            language: 'dart',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });
}
