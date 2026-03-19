import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('runs C++ rules only for sources compiled as C++', () {
    final Map<String, String> sources = <String, String>{
      'c/legacy.c': sourceFixture(
        'cpp/runs_c_rules_only_for_sources_compiled_as_c/legacy.c',
      ),
      'c/legacy.h': '''#define LEGACY_BUFFER_SIZE 4096
#define LEGACY_EMPTY NULL
''',
      'objc/Plugin.m': sourceFixture(
        'cpp/runs_c_rules_only_for_sources_compiled_as_c/Plugin.m',
      ),
      'objc/Plugin.h': '''#define PLUGIN_BUFFER_SIZE 4096
@interface Plugin
@end
''',
      'objcxx/Bridge.mm': sourceFixture(
        'cpp/runs_c_rules_only_for_sources_compiled_as_c/Bridge.mm',
      ),
      'cpp/main.cpp': sourceFixture(
        'cpp/runs_c_rules_only_for_sources_compiled_as_c/main.cpp',
      ),
      'cpp/widget.hpp': '''#define WIDGET_BUFFER_SIZE 4096
#define WIDGET_EMPTY NULL
''',
      'shared/api.h': '''#define SHARED_BUFFER_SIZE 4096
#define SHARED_EMPTY NULL
''',
    };

    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(
          sources,
          AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}),
        )
        .findings;

    expect(findings, isNotEmpty);
    expect(
      findings.map((Finding finding) => finding.path).toSet(),
      everyElement(anyOf(startsWith('cpp/'), startsWith('objcxx/'))),
    );
    expect(
      findings.map((Finding finding) => finding.code),
      containsAll(<String>[
        'cpp-malloc-free',
        'cpp-macro-constant',
        'cpp-null',
      ]),
    );
    expect(
      findings
          .where((Finding finding) => finding.path == 'objcxx/Bridge.mm')
          .map((Finding finding) => finding.code),
      containsAll(<String>['cpp-malloc-free', 'cpp-macro-constant']),
    );
  });

  test('reports C-style casts only in sources compiled as C++', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'legacy.c': 'int narrow(long value) { return (int)value; }',
          'modern.cpp': 'int narrow(long value) { return (int)value; }',
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-cast');

    expect(findings.map((Finding finding) => finding.path), <String>[
      'modern.cpp',
    ]);
  });

  test('does not run C++ modernization rules for a C-only source set', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('cpp').analyze(<
      String,
      String
    >{
      'legacy.c': sourceFixture(
        'cpp/does_not_run_c_modernization_rules_for_a_c_only_source_set/legacy.c',
      ),
      'legacy.h': '''#define BUFFER_SIZE 4096
''',
    }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'})).findings;

    expect(findings, isEmpty);
  });
}
