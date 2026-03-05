import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/generic_rules.dart';
import 'package:test/test.dart';

void main() {
  test('executes a deterministic rule through RuleContext', () {
    const _TodoRule rule = _TodoRule();
    const RuleContext context = RuleContext(
      config: AnalysisConfig(root: '/project'),
      sources: <String, String>{'lib/main.dart': '// TODO'},
      language: 'dart',
    );

    final List<Finding> findings = rule.analyze(context).toList();

    expect(findings.single.code, 'todo');
    expect(findings.single.path, 'lib/main.dart');
  });

  test('indexes rules and rejects duplicate IDs', () {
    final RuleRegistry registry = RuleRegistry(const <CodeBusterRule>[
      _TodoRule(),
    ]);

    expect(registry['todo'], isA<_TodoRule>());
    expect(registry.requirements, <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.tokens,
    });
    expect(
      () => RuleRegistry(const <CodeBusterRule>[_TodoRule(), _TodoRule()]),
      throwsArgumentError,
    );
  });

  test('generic executable rules preserve suspicious-group behavior', () {
    const RuleContext context = RuleContext(
      config: AnalysisConfig(
        root: '/project',
        ruleGroups: <String>{'core', 'suspicious'},
      ),
      sources: <String, String>{
        'lib/main.dart': '// FIXME\nif (value == value) {}',
      },
      language: 'repository',
    );
    final RuleRegistry registry = RuleRegistry(const <CodeBusterRule>[
      FixmeCommentRule(),
      OperationOnSameValueRule(),
    ]);

    expect(
      registry.rules
          .expand((CodeBusterRule rule) => rule.analyze(context))
          .map((Finding finding) => finding.code),
      <String>['fixme-comment', 'operation-on-same-value'],
    );
  });

  test('does not confuse qualified members with local identifiers', () {
    const RuleContext context = RuleContext(
      config: AnalysisConfig(
        root: '/project',
        ruleGroups: <String>{'core', 'suspicious'},
      ),
      sources: <String, String>{
        'lib/main.dart': '''
bool contains(Finding finding) => catalog[finding.code]?.group == group;
List<List<String>> nested = <List<String>>[];
''',
      },
      language: 'repository',
    );

    expect(const OperationOnSameValueRule().analyze(context), isEmpty);
  });

  test('ignores comments, member access, and bitmask containment', () {
    const RuleContext context = RuleContext(
      config: AnalysisConfig(
        root: '/project',
        ruleGroups: <String>{'core', 'suspicious'},
      ),
      sources: <String, String>{
        'main.go': '''
// value == value
/* other == other */
return flags & mask == mask;
return entry->kind == kind;
return node != node.parent;
''',
      },
      language: 'go',
    );

    expect(const OperationOnSameValueRule().analyze(context), isEmpty);
  });

  test('self-contained rules report canonical metadata and overrides', () {
    final SourcePatternRule rule = SourcePatternRule(
      metadata: const RuleMetadata(
        id: 'sample-pattern',
        defaultSeverity: RuleSeverity.info,
        group: 'core',
        title: 'Sample',
        why: 'Canonical explanation.',
        suggestion: 'Canonical remediation.',
      ),
      pattern: RegExp(r'\brisky\('),
      message: 'risky call',
    );
    final List<Finding> findings = rule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(
              root: '/project',
              severityOverrides: <String, RuleSeverity>{
                'sample-pattern': RuleSeverity.warn,
              },
            ),
            sources: <String, String>{'main.dart': 'safe();\nrisky();'},
            language: 'dart',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.severity, RuleSeverity.warn);
    expect(findings.single.line, 2);
    expect(findings.single.why, 'Canonical explanation.');
    expect(findings.single.suggestion, 'Canonical remediation.');
  });

  test('semantic rules receive a checked parse-once representation', () {
    const RuleContext context = RuleContext(
      config: AnalysisConfig(root: '/project'),
      sources: <String, String>{},
      language: 'sample',
      languageAnalysis: <String>['parsed'],
    );

    expect(const _SemanticSampleRule().analyze(context), isEmpty);
  });

  test('validates language-specific analysis types', () {
    const RuleContext context = RuleContext(
      config: AnalysisConfig(root: '/project'),
      sources: <String, String>{},
      language: 'dart',
      languageAnalysis: <String>['parsed'],
    );

    expect(context.requireLanguageAnalysis<List<String>>(), <String>['parsed']);
    expect(
      context.requireLanguageAnalysis<Map<String, String>>,
      throwsStateError,
    );
  });
}

final class _SemanticSampleRule extends SemanticRule<List<String>> {
  const _SemanticSampleRule()
    : super(
        const RuleMetadata(
          id: 'semantic-sample',
          defaultSeverity: RuleSeverity.info,
          group: 'core',
          title: 'Semantic sample',
          why: 'Tests typed analysis.',
          suggestion: 'No action.',
        ),
      );

  @override
  Iterable<Finding> analyzeSemantic(
    RuleContext context,
    List<String> analysis,
  ) {
    expect(analysis, <String>['parsed']);
    return const <Finding>[];
  }
}

final class _TodoRule implements CodeBusterRule {
  const _TodoRule();

  @override
  RuleMetadata get metadata => const RuleMetadata(
    id: 'todo',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'TODO marker',
    why: 'Tracks unfinished work.',
    suggestion: 'Finish the work.',
    semanticMaturity: RuleSemanticMaturity.token,
    requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.tokens},
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (source.value.contains('TODO')) {
        yield Finding(
          code: metadata.id,
          severity: metadata.defaultSeverity,
          path: source.key,
          line: 1,
          message: metadata.title,
        );
      }
    }
  }
}
