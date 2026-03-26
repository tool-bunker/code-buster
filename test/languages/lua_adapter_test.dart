import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('resolves local Lua and Luau require modules', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'scripts/main.luau':
          "local worker = require('scripts.worker')\n"
          'local utility = require "./utility"\n'
          "local package = require('shared')\n",
      'scripts/worker.luau': '',
      'scripts/utility.lua': '',
      'shared/init.lua': '',
    });

    expect(graph.dependenciesOf('scripts/main.luau'), <String>[
      'scripts/utility.lua',
      'scripts/worker.luau',
      'shared/init.lua',
    ]);
  });

  test('resolves bounded Roblox instance require paths', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'src/init.luau': '''
require(script.Types)
require(script.State.Value)
-- require(script.Hidden)
''',
      'src/Types.luau': '',
      'src/State/Value.luau': '',
      'src/State/Computed.luau': sourceFixture(
        'lua/resolves_bounded_roblox_instance_require_paths/Computed.luau',
      ),
      'src/Hidden.luau': '',
    });

    expect(graph.dependenciesOf('src/init.luau'), <String>[
      'src/State/Value.luau',
      'src/Types.luau',
    ]);
    expect(graph.dependenciesOf('src/State/Computed.luau'), <String>[
      'src/State/Value.luau',
      'src/Types.luau',
    ]);
  });

  test('ignores quoted require examples in comments', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'main.luau': "-- local Types = require('./types')\n",
      'types.luau': "require('./main')\n",
    });

    expect(graph.dependenciesOf('main.luau'), isEmpty);
    expect(graph.cycleDependenciesOf('main.luau'), isEmpty);
    expect(GraphAnalysis(graph).cycleFindings(), isEmpty);
  });

  test('resolves modules under the conventional lua source root', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'lua/nvchad/plugins/init.lua':
          "require('nvchad.configs.cmp')\n"
          "require('nvchad.configs.missing')\n",
      'lua/nvchad/configs/cmp.lua': '',
    });

    expect(graph.dependenciesOf('lua/nvchad/plugins/init.lua'), <String>[
      'lua/nvchad/configs/cmp.lua',
    ]);
  });

  test('resolves only literal paths.dofile calls relative to the importer', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'scripts/main.lua': sourceFixture(
        'lua/resolves_only_literal_paths_dofile_calls_relative_to_the_importer/main.lua',
      ),
      'scripts/dataset.lua': '',
      'shared/options.lua': '',
      'scripts/receiver.lua': '',
      'scripts/dynamic.lua': '',
      'scripts/comment.lua': '',
      'scripts/string.lua': '',
    });

    expect(graph.dependenciesOf('scripts/main.lua'), <String>[
      'scripts/dataset.lua',
      'shared/options.lua',
    ]);
  });

  test('lazy function requires stay reachable without creating cycles', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'main.lua': "require('eager')\n",
      'eager.lua': sourceFixture(
        'lua/lazy_function_requires_stay_reachable_without_creating_cycles/eager.lua',
      ),
    });

    expect(graph.dependenciesOf('eager.lua'), <String>['main.lua']);
    expect(graph.cycleDependenciesOf('eager.lua'), isEmpty);
    expect(GraphAnalysis(graph).cycleFindings(), isEmpty);
  });

  test('top-level Lua require cycles remain actionable', () {
    final DependencyGraph graph = LuaGraphAdapter().build(<String, String>{
      'main.lua': "require('eager')\n",
      'eager.lua': "require('main')\n",
    });

    expect(GraphAnalysis(graph).cycleFindings(), hasLength(1));
  });

  test('runner discovers Lua and preserves local reachability', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-lua-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory scripts = Directory(
      '${root.path}${Platform.pathSeparator}scripts',
    )..createSync();
    File(
      '${scripts.path}${Platform.pathSeparator}main.luau',
    ).writeAsStringSync("require('scripts.worker')\n");
    File(
      '${scripts.path}${Platform.pathSeparator}worker.luau',
    ).writeAsStringSync('return {}\n');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>[
        'dead',
        '--root',
        root.path,
        '--lang',
        'luau',
      ]),
    );

    expect(
      run.files.map((SourceFile file) => file.language),
      everyElement('lua'),
    );
    expect(run.graph.dependenciesOf('scripts/main.luau'), <String>[
      'scripts/worker.luau',
    ]);
    expect(
      run.findings.where((Finding finding) => finding.code == 'dead-file'),
      isEmpty,
    );
  });
  test('language manifest emits enabled Lua rules only', () {
    final Map<String, String> sources = <String, String>{
      'main.lua': 'local status = os.execute(command)\n',
    };
    final LanguageAnalysis analysis = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(
          sources,
          AnalysisConfig(
            root: '.',
            severityOverrides: const <String, RuleSeverity>{
              'lua-os-execute': RuleSeverity.error,
            },
          ),
        );

    expect(analysis.findings, hasLength(1));
    expect(analysis.findings.single.code, 'lua-os-execute');
    expect(analysis.findings.single.severity, RuleSeverity.error);
  });
}
