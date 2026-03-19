import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/insecure_tls.dart';
import 'package:test/test.dart';

void main() {
  test('reports disabled TLS verification with sink flow', () {
    final List<Finding> findings = goInsecureTlsRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': 'cfg := tls.Config{InsecureSkipVerify: true}',
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(
      findings.single.codeFlow.single.message,
      'TLS verification disabled here',
    );
  });
}
