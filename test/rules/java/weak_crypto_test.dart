import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/weak_crypto.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports obsolete algorithms only in cryptographic API calls', () {
    final List<Finding> findings = javaWeakCryptoRule
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': sourceFixture(
                'java/rules/weak_crypto_test/reports_obsolete_algorithms_only_in_cryptographic_api_calls/Main.java',
              ),
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(3));
    expect(findings.map((Finding finding) => finding.line), <int>[2, 4, 5]);
  });
}
