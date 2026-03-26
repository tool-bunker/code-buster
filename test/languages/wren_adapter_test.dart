import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'main.wren': sourceFixture('wren/wren_adapter_test/main.wren'),
    'service.wren': 'class Service {}',
  };

  test('resolves imports and extracts Wren methods', () {
    final WrenAdapter adapter = WrenAdapter();
    expect(adapter.buildGraph(sources).dependenciesOf('main.wren'), <String>[
      'service.wren',
    ]);
    expect(
      adapter.functions(sources).map((FunctionSource item) => item.name),
      contains('run'),
    );
  });

  test('emits and catalogues the complete enabled Wren rule pack', () {
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      severityOverrides: <String, RuleSeverity>{
        for (final RuleMetadata rule in RuleCatalog.all.where(
          (RuleMetadata rule) => rule.id.startsWith('wren-'),
        ))
          rule.id: rule.defaultSeverity,
      },
    );
    expect(
      LanguagePluginRegistry.standard()
          .require('wren')
          .analyze(sources, config)
          .findings
          .map((Finding item) => item.code),
      containsAll(<String>[
        'wren-system-print',
        'wren-print-in-loop',
        'wren-number-parse-unchecked',
        'wren-fiber-abort',
      ]),
    );
    expect(config.severityOverrides, hasLength(8));
  });
}
