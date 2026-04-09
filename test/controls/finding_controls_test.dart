import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  const Finding finding = Finding(
    code: 'demo-rule',
    severity: RuleSeverity.warn,
    path: 'lib/sample.dart',
    line: 3,
    message: 'demo finding',
  );

  test(
    'applies disabled rules severity overrides baselines and suppressions',
    () {
      final FindingFilter filter = FindingFilter();
      const AnalysisConfig overridden = AnalysisConfig(
        root: '/project',
        severityOverrides: <String, RuleSeverity>{
          'demo-rule': RuleSeverity.error,
        },
      );
      expect(
        filter
            .apply(config: overridden, findings: <Finding>[finding])
            .single
            .severity,
        RuleSeverity.error,
      );
      expect(
        filter.apply(
          config: const AnalysisConfig(
            root: '/project',
            disabledRules: <String>{'demo-rule'},
          ),
          findings: <Finding>[finding],
        ),
        isEmpty,
      );
      expect(
        filter.apply(
          config: overridden,
          findings: <Finding>[finding],
          baseline: <String>{finding.fingerprint},
        ),
        isEmpty,
      );
      expect(
        filter.apply(
          config: overridden,
          findings: <Finding>[finding],
          sources: const <String, String>{
            'lib/sample.dart':
                'final text = "// code-buster-ignore demo-rule";\n// code-buster-ignore demo-rule\nrun();',
          },
        ),
        isEmpty,
      );
    },
  );

  test('supports file-level suppressions and does not interpret string text', () {
    final FindingFilter filter = FindingFilter();
    expect(
      filter.apply(
        config: const AnalysisConfig(root: '/project'),
        findings: <Finding>[finding],
        sources: const <String, String>{
          'lib/sample.dart':
              'final text = "// code-buster-ignore-file demo-rule";\nrun();\nwarn();',
        },
      ),
      hasLength(1),
    );
    expect(
      filter.apply(
        config: const AnalysisConfig(root: '/project'),
        findings: <Finding>[finding],
        sources: const <String, String>{
          'lib/sample.dart':
              '// code-buster-ignore-file demo-rule\nrun();\nwarn();',
        },
      ),
      isEmpty,
    );
    const Finding nimFinding = Finding(
      code: 'demo-rule',
      severity: RuleSeverity.warn,
      path: 'src/sample.nim',
      line: 3,
      message: 'demo finding',
    );
    expect(
      filter.apply(
        config: const AnalysisConfig(root: '/project'),
        findings: const <Finding>[nimFinding],
        sources: const <String, String>{
          'src/sample.nim':
              '# code-buster-ignore-file demo-rule: parity test\nrun()\nwarn()',
        },
      ),
      isEmpty,
    );
  });

  test(
    'round-trips JSON baselines and accepts legacy fingerprint lists',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-baseline-',
      );
      addTearDown(() => root.delete(recursive: true));
      final File jsonFile = File('${root.path}/baseline.json');
      BaselineCodec.write(jsonFile, <Finding>[finding]);

      expect(
        BaselineCodec.read(jsonFile),
        containsAll(<String>{finding.key, finding.fingerprint}),
      );
      final Map<String, dynamic> ledger =
          jsonDecode(jsonFile.readAsStringSync()) as Map<String, dynamic>;
      expect(ledger['schemaVersion'], 2);
      expect(ledger['kind'], 'code-buster-triage-ledger');
      final Map<String, dynamic> entry =
          (ledger['entries'] as List<dynamic>).single as Map<String, dynamic>;
      expect(entry['status'], 'accepted');
      expect(entry['reason'], 'baseline snapshot');
      expect(entry['rule_version'], 1);
      expect(entry['history'], hasLength(1));

      entry['status'] = 'false-positive';
      entry['owner'] = 'platform-team';
      jsonFile.writeAsStringSync(jsonEncode(ledger));
      BaselineCodec.write(jsonFile, <Finding>[finding]);
      final Map<String, dynamic> preserved =
          jsonDecode(jsonFile.readAsStringSync()) as Map<String, dynamic>;
      final Map<String, dynamic> preservedEntry =
          (preserved['entries'] as List<dynamic>).single
              as Map<String, dynamic>;
      expect(preservedEntry['status'], 'false-positive');
      expect(preservedEntry['owner'], 'platform-team');

      final File fixedFile = File('${root.path}/fixed.json')
        ..writeAsStringSync(
          jsonEncode(<String, Object>{
            'schemaVersion': 2,
            'entries': <Map<String, Object>>[
              <String, Object>{
                'status': 'fixed',
                'fingerprint': finding.fingerprint,
                'code': finding.code,
                'path': finding.path,
                'message': finding.message,
              },
            ],
          }),
        );
      expect(BaselineCodec.read(fixedFile), isEmpty);

      final File legacyFile = File('${root.path}/baseline.txt')
        ..writeAsStringSync('# old\n${finding.fingerprint}\n');
      expect(BaselineCodec.read(legacyFile), <String>{finding.fingerprint});
    },
  );

  test(
    'evaluates configured pattern rules against code but not comments or strings',
    () {
      const PatternRule rule = PatternRule(
        id: 'no-debug',
        severity: RuleSeverity.warn,
        pattern: r'debugCall\(',
        patternNot: 'allowed',
        message: 'debug call committed',
        suggestion: 'Remove it.',
        fix: 'remove',
        category: 'reliability',
      );
      final List<Finding> findings = PatternRuleAnalysis().findings(
        <String, String>{
          'lib/sample.dart': '''
debugCall(value);
// debugCall(comment);
final text = "debugCall(string)";
debugCall(allowed);
''',
        },
        <PatternRule>[rule],
      );

      expect(findings, hasLength(1));
      expect(findings.single.line, 1);
      expect(findings.single.suggestion, 'Remove it. Fix: remove');
    },
  );
}
