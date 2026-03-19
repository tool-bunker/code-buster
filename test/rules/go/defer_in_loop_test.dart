import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/defer_in_loop.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports defer inside a loop but not outside', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': sourceFixture(
                'go/rules/defer_in_loop_test/reports_defer_inside_a_loop_but_not_outside/main.go',
              ),
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });
}
