import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'go.mod': 'module example.com/project\n',
    'cmd/app/main.go': sourceFixture('go/go_adapter_test/main.go'),
    'internal/service/service.go': sourceFixture(
      'go/go_adapter_test/service.go',
    ),
  };

  test('resolves module imports and extracts functions', () {
    final GoAdapter adapter = GoAdapter();
    expect(
      adapter.buildGraph(sources).dependenciesOf('cmd/app/main.go'),
      <String>['internal/service/service.go'],
    );
    expect(
      adapter
          .functions(sources)
          .map((FunctionSource function) => function.name),
      <String>['main', 'Run'],
    );
  });

  test('does not resolve package imports to external test files', () {
    const Map<String, String> externalTestSources = <String, String>{
      'go.mod': 'module example.com/project\n',
      'service/service.go': 'package service\n',
      'service/service_test.go': '''
package service_test
import "example.com/project/service"
''',
      'service/mocks/mock.go': '''
package mocks
import "example.com/project/service"
''',
    };

    final DependencyGraph graph = GoAdapter().buildGraph(externalTestSources);

    expect(graph.dependenciesOf('service/mocks/mock.go'), <String>[
      'service/service.go',
    ]);
    expect(GraphAnalysis(graph).cycleFindings(), isEmpty);
  });
}
