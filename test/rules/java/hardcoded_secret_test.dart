import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/hardcoded_secret.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports literal credentials but accepts environment lookups', () {
    final List<Finding> findings = const JavaHardcodedSecretRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': sourceFixture(
                'java/rules/hardcoded_secret_test/reports_literal_credentials_but_accepts_environment_lookups/Main.java',
              ),
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(2));
    expect(findings.map((Finding finding) => finding.line), <int>[1, 14]);
  });
}
