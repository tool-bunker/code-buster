import 'dart:io';

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

  test('includes registered Go findings in repository results', () {
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(
        root: '/project',
        languages: <String>['go'],
        ruleGroups: <String>{'security'},
      ),
      files: const <SourceFile>[
        SourceFile(
          absolutePath: '/project/main.go',
          relativePath: 'main.go',
          language: 'go',
        ),
      ],
      sources: const <String, String>{
        'main.go': '''
package main
import "os"
func main() { _ = os.WriteFile("ready", nil, 0o777) }
''',
      },
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );

    final List<Finding> findings = RuleExecutionStage().execute(
      CodeBusterCommand.summary,
      LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
      GraphAnalysis(DependencyGraph(const <String, Iterable<String>>{})),
    );

    expect(
      findings.map((Finding finding) => finding.code),
      contains('go-world-writable'),
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

  test('keeps workspace package internals reachable from public roots', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code_buster_dead_workspace_',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    Directory('${root.path}/app').createSync();
    File(
      '${root.path}/app/pubspec.yaml',
    ).writeAsStringSync('name: localsend_app\n');
    Directory('${root.path}/packages/isolates').createSync(recursive: true);
    File(
      '${root.path}/packages/isolates/pubspec.yaml',
    ).writeAsStringSync('name: localsend_isolates\n');
    const Map<String, String> sources = <String, String>{
      'app/lib/main.dart':
          "import 'package:localsend_app/src/home.dart';\n"
          "import 'package:localsend_isolates/localsend_isolates.dart';\n"
          'void main() {}',
      'app/lib/src/home.dart': '',
      'packages/isolates/lib/localsend_isolates.dart':
          "export 'src/worker.dart';",
      'packages/isolates/lib/src/worker.dart': '',
      'packages/isolates/lib/src/orphan.dart': '',
    };
    final AnalysisConfig config = AnalysisConfig(root: root.path);
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: root.path,
      config: config,
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final LanguageAnalysis dart = LanguagePluginRegistry.standard()
        .require('dart')
        .analyze(sources, config);

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dart.graph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'packages/isolates/lib/src/orphan.dart',
    ]);
  });

  test('keeps Dart sources reachable through generated routers', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code_buster_dead_generated_router_',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    Directory('${root.path}/lib/routes').createSync(recursive: true);
    File('${root.path}/lib/routes/app_router.g.dart').writeAsStringSync('''
// GENERATED CODE - DO NOT MODIFY BY HAND
import 'package:app/pages/home.dart';
''');
    const Map<String, String> sources = <String, String>{
      'lib/main.dart': "import 'routes/app_router.dart';\nvoid main() {}\n",
      'lib/routes/app_router.dart': '',
      'lib/pages/home.dart': "import '../widgets/player.dart';\n",
      'lib/widgets/player.dart': '',
      'lib/widgets/orphan.dart': '',
    };
    final AnalysisConfig config = AnalysisConfig(root: root.path);
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: root.path,
      config: config,
      files: const <SourceFile>[],
      sources: sources,
      generatedProvenance: const <GeneratedSourceProvenance>[
        GeneratedSourceProvenance(
          path: 'lib/routes/app_router.g.dart',
          reason: 'matched generated filename convention',
          source: 'built-in generated policy',
        ),
      ],
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final LanguageAnalysis dart = LanguagePluginRegistry.standard()
        .require('dart')
        .analyze(sources, config);

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dart.graph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'lib/widgets/orphan.dart',
    ]);
  });

  test('uses Dart builder libraries declared by nested packages as roots', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code_buster_dead_builder_',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    Directory('${root.path}/packages/codegen').createSync(recursive: true);
    File(
      '${root.path}/packages/codegen/pubspec.yaml',
    ).writeAsStringSync('name: codegen\n');
    File('${root.path}/packages/codegen/build.yaml').writeAsStringSync('''
builders:
  codegen:
    import: "package:codegen/src/generator.dart"
    builder_factories: ["createBuilder"]
''');
    const Map<String, String> sources = <String, String>{
      'packages/codegen/lib/src/generator.dart':
          "import 'reachable.dart';\nBuilder createBuilder() => Builder();",
      'packages/codegen/lib/src/reachable.dart': '',
      'packages/codegen/lib/src/orphan.dart': '',
    };
    final AnalysisConfig config = AnalysisConfig(root: root.path);
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: root.path,
      config: config,
      files: const <SourceFile>[],
      sources: sources,
      changedLineRanges: const <String, List<ChangedLineRange>>{},
    );
    final LanguageAnalysis dart = LanguagePluginRegistry.standard()
        .require('dart')
        .analyze(sources, config);

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dart.graph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles.map((Finding finding) => finding.path), <String>[
      'packages/codegen/lib/src/orphan.dart',
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

  test('treats nested Python src-layout packages as public roots', () {
    const Map<String, String> sources = <String, String>{
      'packages/tool/src/tool/__init__.py': 'from .api import convert\n',
      'packages/tool/src/tool/api.py': 'def convert(): return 1\n',
      'packages/tool/src/tool/converters/pdf.py':
          'def convert_pdf(): return 1\n',
      'packages/tool/tests/test_api.py': 'def test_api(): pass\n',
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
        'packages/tool/src/tool/__init__.py': <String>[
          'packages/tool/src/tool/api.py',
        ],
        'packages/tool/src/tool/api.py': <String>[],
        'packages/tool/src/tool/converters/pdf.py': <String>[],
        'packages/tool/tests/test_api.py': <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles, isEmpty);
  });

  test('treats top-level Python namespace packages as public roots', () {
    const Map<String, String> sources = <String, String>{
      'main.py': 'import engine.runtime\n',
      'engine/runtime.py': 'value = 1\n',
      'engine/plugins/optional.py': 'value = 2\n',
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
        'main.py': <String>['engine/runtime.py'],
        'engine/runtime.py': <String>[],
        'engine/plugins/optional.py': <String>[],
      },
    );

    final Iterable<Finding> deadFiles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.dead,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'dead-file');

    expect(deadFiles, isEmpty);
  });

  test('does not report ordinary Rust module reference cycles', () {
    const Map<String, String> sources = <String, String>{
      'src/main.rs': 'mod model;',
      'src/model.rs': 'use crate::view::View;',
      'src/view.rs': 'use crate::model::Model;',
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
        'src/main.rs': <String>['src/model.rs'],
        'src/model.rs': <String>['src/view.rs'],
        'src/view.rs': <String>['src/model.rs'],
      },
    );

    final Iterable<Finding> cycles = RuleExecutionStage()
        .execute(
          CodeBusterCommand.summary,
          LanguageIndexStage(LanguagePluginRegistry.standard()).build(prepared),
          GraphAnalysis(dependencyGraph),
        )
        .where((Finding finding) => finding.code == 'cycle');

    expect(cycles, isEmpty);
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
