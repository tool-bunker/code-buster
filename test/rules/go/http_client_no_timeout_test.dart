import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/http_client_no_timeout.dart';
import 'package:test/test.dart';

void main() {
  test('reports empty HTTP clients but accepts configured timeouts', () {
    final List<Finding> findings = goHttpClientNoTimeoutRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': '''plain := http.Client{}
bounded := http.Client{Timeout: time.Second}
''',
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });
}
