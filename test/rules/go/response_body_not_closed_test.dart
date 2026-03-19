import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/response_body_not_closed.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports only HTTP responses not closed in their function', () {
    final List<Finding> findings = const GoResponseBodyNotClosedRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'client.go': sourceFixture(
                'go/rules/response_body_not_closed_test/reports_only_http_responses_not_closed_in_their_function/client.go',
              ),
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'go-response-body-not-closed');
    expect(findings.single.line, 3);
  });
}
