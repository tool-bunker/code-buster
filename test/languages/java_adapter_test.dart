import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'Main.java': sourceFixture('java/java_adapter_test/Main.java'),
    'Service.java': sourceFixture('java/java_adapter_test/Service.java'),
  };

  test('resolves project-owned Java types and extracts methods', () {
    final JavaAdapter adapter = JavaAdapter();
    expect(adapter.buildGraph(sources).dependenciesOf('Main.java'), <String>[
      'Service.java',
    ]);
    expect(
      adapter.functions(sources).map((FunctionSource item) => item.name),
      containsAll(<String>['main', 'load']),
    );
  });

  test('does not extract control-flow branches as methods', () {
    final List<FunctionSource>
    functions = JavaAdapter().functions(<String, String>{
      'Branches.java': sourceFixture(
        'java/does_not_extract_control_flow_branches_as_methods/Branches.java',
      ),
    });

    expect(functions.map((FunctionSource item) => item.name), <String>[
      'check',
    ]);
  });
  test('distinguishes string identity from char and numeric comparisons', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('java')
        .analyze(<String, String>{
          'Comparisons.java': sourceFixture(
            'java/distinguishes_string_identity_from_char_and_numeric_comparisons/Comparisons.java',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'java-string-equals')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 9);
  });

  test('ignores non-string operands near Java string literals', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('java')
        .analyze(<String, String>{
          'Comparisons.java': sourceFixture(
            'java/ignores_non_string_operands_near_java_string_literals/Comparisons.java',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'java-string-equals')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 9);
  });

  test('ignores Java metadata and examples that name secrets', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('java')
        .analyze(<String, String>{
          'Metadata.java': sourceFixture(
            'java/ignores_java_metadata_and_examples_that_name_secrets/Metadata.java',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'security'}))
        .findings
        .where((Finding finding) => finding.code == 'java-hardcoded-secret')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 8);
  });
}
