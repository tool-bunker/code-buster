import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/architecture/architecture.dart';
import 'package:test/test.dart';

void main() {
  final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
    'src/ui/view.dart': <String>['src/domain/model.dart'],
    'src/domain/model.dart': <String>['src/data/store.dart'],
    'src/data/store.dart': <String>['src/ui/view.dart'],
  });
  final AnalysisConfig config = AnalysisConfig(
    root: '.',
    architectureLayers: const <String>['ui', 'domain', 'data'],
    architectureAllowedDependencies: const <String>[
      'ui -> domain',
      'domain -> data',
    ],
    architectureDeniedDependencies: const <String>['data -> ui'],
  );

  test('matches wildcard and segment layer patterns in declaration order', () {
    expect(
      ArchitectureAnalysis(graph, config).layerFor('src/ui/view.dart'),
      'ui',
    );
    final AnalysisConfig wildcard = AnalysisConfig(
      root: '.',
      architectureLayers: const <String>['src/*/internal'],
    );
    expect(
      ArchitectureAnalysis(graph, wildcard).layerFor('src/pkg/internal/a.dart'),
      'src/*/internal',
    );
  });

  test('reports denied edges and layer cycles', () {
    final List<Finding> findings = ArchitectureAnalysis(
      graph,
      config,
    ).findings();
    expect(
      findings.map((Finding item) => item.code),
      containsAll(<String>[
        'architecture-forbidden-dependency',
        'architecture-layer-cycle',
      ]),
    );
    expect(
      findings
          .singleWhere(
            (Finding item) => item.code == 'architecture-forbidden-dependency',
          )
          .relatedFiles,
      <String>['src/ui/view.dart'],
    );
  });

  test('renders stable Mermaid layer edges', () {
    expect(ArchitectureAnalysis(graph, config).mermaid(), '''graph TD
  "data" --> "ui"
  "domain" --> "data"
  "ui" --> "domain"
''');
  });
}
