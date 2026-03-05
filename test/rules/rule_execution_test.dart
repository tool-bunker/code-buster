import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('executes registered repository rules independently of the runner', () {
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(
        root: '/project',
        languages: <String>['dart'],
        ruleGroups: <String>{'core', 'suspicious'},
      ),
      files: const <SourceFile>[],
      sources: const <String, String>{
        'lib/main.dart': '// TODO\nvoid main() {}\n',
      },
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );

    final List<Finding> findings = RuleExecutionStage().execute(
      CodeBusterCommand.summary,
      LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
      GraphAnalysis(DependencyGraph(const <String, Iterable<String>>{})),
    );

    expect(
      findings.where((Finding finding) => finding.code == 'todo-comment'),
      hasLength(1),
    );
  });

  test('does not report runner-discovered test scripts as dead files', () {
    const Map<String, String> sources = <String, String>{
      'scripts/main.lua': '',
      'scripts/orphan.lua': '',
      'tests/scripts/clipboard.lua': '',
      '__tests__/fixtures/torture.lua': '',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      sources.map(
        (String path, String source) =>
            MapEntry<String, Iterable<String>>(path, const <String>[]),
      ),
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'scripts/orphan.lua',
    ]);
  });

  test('does not infer dead Lua files without a reliable entry point', () {
    const Map<String, String> sources = <String, String>{
      'scripts/one.lua': '',
      'scripts/two.lua': '',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      sources.map(
        (String path, String source) =>
            MapEntry<String, Iterable<String>>(path, const <String>[]),
      ),
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles, isEmpty);
  });

  test('uses conventional repository init modules as Lua roots', () {
    const Map<String, String> sources = <String, String>{
      'init.lua': '',
      'root_dependency.lua': '',
      'src/init.luau': '',
      'src/dependency.luau': '',
      'src/orphan.luau': '',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      const <String, Iterable<String>>{
        'init.lua': <String>['root_dependency.lua'],
        'root_dependency.lua': <String>[],
        'src/init.luau': <String>['src/dependency.luau'],
        'src/dependency.luau': <String>[],
        'src/orphan.luau': <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'src/orphan.luau',
    ]);
  });

  test('uses conventional Lua package modules as public loader roots', () {
    const Map<String, String> sources = <String, String>{
      'lua/acme/init.lua': '',
      'lua/acme/config.lua': '',
      'lua/acme/plugins/example.lua': '',
      'lua/acme/internal/reachable.lua': '',
      'lua/acme/plugins/configs/reachable.lua': '',
      'lua/acme/_private/orphan.lua': '',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      <String, Iterable<String>>{
        'lua/acme/init.lua': const <String>['lua/acme/internal/reachable.lua'],
        'lua/acme/config.lua': const <String>[],
        'lua/acme/plugins/example.lua': const <String>[
          'lua/acme/plugins/configs/reachable.lua',
        ],
        'lua/acme/internal/reachable.lua': const <String>[],
        'lua/acme/plugins/configs/reachable.lua': const <String>[],
        'lua/acme/_private/orphan.lua': const <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'lua/acme/_private/orphan.lua',
    ]);
  });

  test('uses conventional Neovim runtime scripts as loader roots', () {
    const Map<String, String> sources = <String, String>{
      'plugin/acme.lua': '',
      'ftplugin/acme.lua': '',
      'lua/acme/internal/plugin_dependency.lua': '',
      'lua/acme/internal/ftplugin_dependency.lua': '',
      'lua/acme/internal/orphan.lua': '',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      <String, Iterable<String>>{
        'plugin/acme.lua': const <String>[
          'lua/acme/internal/plugin_dependency.lua',
        ],
        'ftplugin/acme.lua': const <String>[
          'lua/acme/internal/ftplugin_dependency.lua',
        ],
        'lua/acme/internal/plugin_dependency.lua': const <String>[],
        'lua/acme/internal/ftplugin_dependency.lua': const <String>[],
        'lua/acme/internal/orphan.lua': const <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'lua/acme/internal/orphan.lua',
    ]);
  });

  test('reports unreachable Dart implementation files from package roots', () {
    const Map<String, String> sources = <String, String>{
      'lib/code_buster.dart': "export 'src/reachable.dart';\n",
      'lib/src/reachable.dart': 'void reachable() {}\n',
      'lib/src/orphan.dart': 'void orphan() {}\n',
      'test/orphan_test.dart': 'void main() {}\n',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      const <String, Iterable<String>>{
        'lib/code_buster.dart': <String>['lib/src/reachable.dart'],
        'lib/src/reachable.dart': <String>[],
        'lib/src/orphan.dart': <String>[],
        'test/orphan_test.dart': <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'lib/src/orphan.dart',
    ]);
  });

  test('reports unreachable Python modules from configured script roots', () {
    const Map<String, String> sources = <String, String>{
      'tool/release.py': 'from package import reachable\n',
      'package/reachable.py': 'value = 1\n',
      'package/orphan.py': 'value = 2\n',
      'tests/test_orphan.py': 'value = 3\n',
    };
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(
        root: '/project',
        entryPoints: <String>['tool/release.py'],
      ),
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final DependencyGraph dependencyGraph = DependencyGraph(
      const <String, Iterable<String>>{
        'tool/release.py': <String>['package/reachable.py'],
        'package/reachable.py': <String>[],
        'package/orphan.py': <String>[],
        'tests/test_orphan.py': <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'package/orphan.py',
    ]);
  });

  test('returns no findings for graph output command', () {
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project'),
      files: const <SourceFile>[],
      sources: const <String, String>{},
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );

    expect(
      RuleExecutionStage().execute(
        CodeBusterCommand.graph,
        LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
        GraphAnalysis(DependencyGraph(const <String, Iterable<String>>{})),
      ),
      isEmpty,
    );
  });
}
