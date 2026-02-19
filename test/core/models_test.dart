import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  group('RuleSeverity', () {
    test('normalizes the legacy warning alias', () {
      expect(RuleSeverity.parse('warning'), RuleSeverity.warn);
      expect(RuleSeverity.warn.configValue, 'warn');
    });

    test('rejects unsupported values', () {
      expect(() => RuleSeverity.parse('critical'), throwsFormatException);
    });
  });

  group('Finding', () {
    test('uses the legacy stable baseline key and SHA-256 fingerprint', () {
      const Finding finding = Finding(
        code: 'duplicate-block',
        severity: RuleSeverity.warn,
        path: 'lib/a.dart',
        line: 10,
        message: 'same',
      );

      expect(finding.key, 'duplicate-block|lib/a.dart|same');
      expect(finding.fingerprint, '67CDAC5B6020');
    });
  });

  test('AnalysisConfig preserves Code Buster-compatible defaults', () {
    const AnalysisConfig config = AnalysisConfig(root: '/project');

    expect(config.minDuplicationLines, 15);
    expect(
      config.ruleGroups,
      containsAll(<String>['core', 'security', 'style']),
    );
    expect(config.groupModes, isEmpty);
    expect(config.ruleModes, isEmpty);
    expect(config.severityOverrides, isEmpty);
  });
}
