import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/resource_not_closed.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports only locally-owned unclosed Java resources', () {
    final Map<String, String> sources = <String, String>{
      'Files.java': sourceFixture(
        'java/rules/resource_not_closed_test/reports_only_locally_owned_unclosed_java_resources/Files.java',
      ),
    };
    final Iterable<Finding> findings = const JavaResourceNotClosedRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: sources,
            language: 'java',
          ),
        );

    expect(findings, hasLength(1));
    expect(findings.single.code, 'java-resource-not-closed');
    expect(findings.single.line, 3);
  });
}
