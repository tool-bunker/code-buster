import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/string_equals.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports literal identity comparisons without conflating expressions', () {
    final List<Finding> findings = javaStringEqualsRule
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': sourceFixture(
                'java/rules/string_equals_test/reports_literal_identity_comparisons_without_conflating_expressions/Main.java',
              ),
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(2));
    expect(findings.map((Finding finding) => finding.line), <int>[1, 2]);
  });
}
