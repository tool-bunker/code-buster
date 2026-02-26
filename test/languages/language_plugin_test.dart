import 'package:analyzer/dart/ast/ast.dart';
import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('indexes language plugins and rejects duplicate IDs', () {
    final LanguagePluginRegistry registry = LanguagePluginRegistry(
      const <LanguagePlugin>[_TestPlugin('demo')],
    );

    expect(registry['DEMO']?.id, 'demo');
    expect(registry.require('demo'), isA<_TestPlugin>());
    expect(() => registry.require('missing'), throwsStateError);
    expect(
      () => LanguagePluginRegistry(const <LanguagePlugin>[
        _TestPlugin('demo'),
        _TestPlugin('DEMO'),
      ]),
      throwsArgumentError,
    );
  });

  test('language index invokes each plugin once and reuses its result', () {
    final _CountingPlugin plugin = _CountingPlugin();
    final LanguagePluginRegistry registry = LanguagePluginRegistry(
      <LanguagePlugin>[plugin],
    );
    final IndexedAnalysis indexed = LanguageIndexStage(registry).build(
      const PreparedAnalysis(
        root: '/project',
        config: AnalysisConfig(root: '/project'),
        files: <SourceFile>[],
        sources: <String, String>{},
        changedLineRanges: <String, List<ChangedLineRange>>{},
      ),
    );

    GraphConstructionStage(registry).build(indexed);
    indexed.require('counting').functions;
    indexed.require('counting').findings;

    expect(plugin.analysisCalls, 1);
  });

  test('Dart plugin defers canonical line wrapping to dart format', () {
    final LanguageAnalysis
    analysis = DartLanguagePlugin().analyze(const <String, String>{
      'lib/main.dart':
          'final values = <({String first, String second, String third, String fourth, String fifth})>[];\n',
    }, const AnalysisConfig(root: '.'));

    expect(
      analysis.findings.where((Finding finding) => finding.code == 'long-line'),
      isEmpty,
    );
  });

  test('Dart plugin exposes its shared parsed-unit representation', () {
    final LanguageAnalysis analysis = DartLanguagePlugin()
        .analyze(const <String, String>{
          'lib/main.dart': "import 'helper.dart';\nvoid main() {}\n",
          'lib/helper.dart': 'void helper() {}\n',
        }, const AnalysisConfig(root: '/project'));

    expect(analysis.graph.dependenciesOf('lib/main.dart'), <String>[
      'lib/helper.dart',
    ]);
    expect(analysis.representation, isA<Map<String, CompilationUnit>>());
  });

  test('standard registry exposes every built-in language plugin', () {
    expect(
      LanguagePluginRegistry.standard().plugins.map(
        (LanguagePlugin plugin) => plugin.id,
      ),
      <String>[
        'cpp',
        'csharp',
        'css',
        'dart',
        'html',
        'go',
        'java',
        'javascript',
        'lua',
        'nim',
        'python',
        'sql',
        'wren',
      ],
    );
    final LanguagePlugin plugin = LanguagePluginRegistry.standard().require(
      'wren',
    );
    const Map<String, String> sources = <String, String>{
      'main.wren': 'import "other" for Other\nmain() {}',
      'other.wren': 'class Other {}',
    };

    expect(
      plugin
          .buildGraph(sources, const AnalysisConfig(root: '/project'))
          .dependenciesOf('main.wren'),
      <String>['other.wren'],
    );
    expect(plugin.functions(sources), isNotEmpty);
  });
}

final class _CountingPlugin implements LanguagePlugin {
  var analysisCalls = 0;

  @override
  String get id => 'counting';

  @override
  Set<String> get sourceLanguageIds => <String>{'counting'};

  @override
  LanguageAnalysis analyze(Map<String, String> sources, AnalysisConfig config) {
    analysisCalls++;
    return LanguageAnalysis(
      graph: DependencyGraph(const <String, Iterable<String>>{}),
      functions: const <FunctionSource>[],
      findings: const <Finding>[],
    );
  }

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => throw UnsupportedError('LanguageIndexStage must call analyze once');

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      throw UnsupportedError('LanguageIndexStage must reuse analysis');
}

final class _TestPlugin implements LanguagePlugin {
  const _TestPlugin(this.id);

  @override
  final String id;

  @override
  Set<String> get sourceLanguageIds => <String>{id};

  @override
  LanguageAnalysis analyze(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => LanguageAnalysis(
    graph: buildGraph(sources, config),
    functions: functions(sources),
    findings: const <Finding>[],
  );

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => DependencyGraph(const <String, Iterable<String>>{});

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}
