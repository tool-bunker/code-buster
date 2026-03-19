import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/sql_string_build.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports dynamic SQL concatenation but ignores non-SQL text', () {
    final List<Finding> findings = javaSqlStringBuildRule
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': sourceFixture(
                'java/rules/sql_string_build_test/reports_dynamic_sql_concatenation_but_ignores_non_sql_text/Main.java',
              ),
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(4));
    expect(findings.map((Finding finding) => finding.line), <int>[1, 2, 3, 4]);
  });
}
