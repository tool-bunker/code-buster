import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test(
    'partitions findings once while preserving source order and summaries',
    () {
      const AnalysisConfig config = AnalysisConfig(
        root: '/project',
        ruleModes: <String, RuleMode>{
          'report-one': RuleMode.report,
          'aggregation-advisory-fixture': RuleMode.count,
          'report-two': RuleMode.report,
          'disabled-one': RuleMode.off,
        },
      );
      const List<Finding> findings = <Finding>[
        Finding(
          code: 'aggregation-advisory-fixture',
          severity: RuleSeverity.info,
          path: 'lib/a.dart',
          line: 1,
          message: 'advisory',
        ),
        Finding(
          code: 'report-one',
          severity: RuleSeverity.warn,
          path: 'src/b.py',
          line: 2,
          message: 'actionable',
        ),
        Finding(
          code: 'disabled-one',
          severity: RuleSeverity.warn,
          path: 'lib/a.dart',
          line: 3,
          message: 'disabled',
        ),
        Finding(
          code: 'report-two',
          severity: RuleSeverity.error,
          path: 'lib/a.dart',
          line: 4,
          message: 'actionable',
        ),
      ];
      final AnalysisRun run = AnalysisRun(
        config: config,
        files: const <SourceFile>[
          SourceFile(
            absolutePath: '/project/lib/a.dart',
            relativePath: 'lib/a.dart',
            language: 'dart',
          ),
          SourceFile(
            absolutePath: '/project/src/b.py',
            relativePath: 'src/b.py',
            language: 'python',
          ),
        ],
        sources: const <String, String>{},
        graph: DependencyGraph(const <String, Iterable<String>>{}),
        findings: findings,
      );

      expect(
        run.activeFindings.map((Finding finding) => finding.code),
        <String>['aggregation-advisory-fixture', 'report-one', 'report-two'],
      );
      expect(
        run.actionableFindings.map((Finding finding) => finding.code),
        <String>['report-one', 'report-two'],
      );
      expect(
        run.advisoryFindings.map((Finding finding) => finding.code),
        <String>['aggregation-advisory-fixture'],
      );
      expect(run.advisorySummary, <String, int>{'security': 1});
      expect(run.languageSummaryFor(run.activeFindings), <String, Object>{
        'dart': <String, int>{'files': 1, 'findings': 2},
        'python': <String, int>{'files': 1, 'findings': 1},
      });
    },
  );

  test('aggregates large mixed finding sets without changing counts', () {
    const AnalysisConfig config = AnalysisConfig(
      root: '/project',
      ruleModes: <String, RuleMode>{
        'bulk-report': RuleMode.report,
        'bulk-count': RuleMode.count,
      },
    );
    final List<Finding> findings = List<Finding>.generate(
      10000,
      (int index) => Finding(
        code: index.isEven ? 'bulk-report' : 'bulk-count',
        severity: RuleSeverity.info,
        path: 'lib/a.dart',
        line: index + 1,
        message: 'finding $index',
      ),
      growable: false,
    );
    final AnalysisRun run = AnalysisRun(
      config: config,
      files: const <SourceFile>[
        SourceFile(
          absolutePath: '/project/lib/a.dart',
          relativePath: 'lib/a.dart',
          language: 'dart',
        ),
      ],
      sources: const <String, String>{},
      graph: DependencyGraph(const <String, Iterable<String>>{}),
      findings: findings,
    );

    expect(run.activeFindings, hasLength(10000));
    expect(run.actionableFindings, hasLength(5000));
    expect(run.advisoryFindings, hasLength(5000));
    expect(run.advisorySummary.values.single, 5000);
    expect(run.languageSummaryFor(run.activeFindings)['dart'], <String, int>{
      'files': 1,
      'findings': 10000,
    });
  });
}
