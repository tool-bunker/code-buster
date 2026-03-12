import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('resolves local ESM CommonJS and extensionless dependencies', () {
    final DependencyGraph graph = JavaScriptGraphAdapter()
        .build(<String, String>{
          'src/main.ts':
              "import { worker } from './worker';\n"
              "export { helper } from './helpers';\n"
              "const tool = require('./tool');\n",
          'src/worker.mts': '',
          'src/helpers/index.ts': '',
          'src/tool.cjs': '',
        });

    expect(graph.dependenciesOf('src/main.ts'), <String>[
      'src/helpers/index.ts',
      'src/tool.cjs',
      'src/worker.mts',
    ]);
  });

  test('does not create runtime dependencies for type-only declarations', () {
    final DependencyGraph graph = JavaScriptGraphAdapter()
        .build(<String, String>{
          'src/main.ts':
              "import type { Worker } from './worker';\n"
              "export type { Result } from './result';\n"
              "import { run } from './runtime';\n",
          'src/worker.ts': '',
          'src/result.ts': '',
          'src/runtime.ts': '',
        });

    expect(graph.dependenciesOf('src/main.ts'), <String>['src/runtime.ts']);
  });

  test('extracts named functions, methods, and block arrow functions', () {
    final List<FunctionSource>
    functions = JavaScriptFunctionAnalysis().functions(<String, String>{
      'src/main.ts': sourceFixture(
        'javascript/extracts_named_functions_methods_and_block_arrow_functions/main.ts',
      ),
    });

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'parse',
      'execute',
      'validate',
    ]);
    expect(functions.map((FunctionSource function) => function.line), <int>[
      1,
      6,
      10,
    ]);
  });

  test('regex literals cannot consume following JavaScript functions', () {
    final List<FunctionSource>
    functions = JavaScriptFunctionAnalysis().functions(<String, String>{
      'src/main.js': sourceFixture(
        'javascript/regex_literals_cannot_consume_following_javascript_functions/main.js',
      ),
    });
    final RepositoryAnalysis analysis = RepositoryAnalysis();

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'stripFences',
      'following',
    ]);
    expect(functions.first.source.split('\n'), hasLength(3));
    expect(analysis.measure(functions.first).cyclomatic, 1);
  });

  test('measures nested JavaScript functions independently', () {
    final List<FunctionSource>
    functions = JavaScriptFunctionAnalysis().functions(<String, String>{
      'src/main.js': sourceFixture(
        'javascript/measures_nested_javascript_functions_independently/main.js',
      ),
    });
    final RepositoryAnalysis analysis = RepositoryAnalysis();

    expect(functions, hasLength(3));
    expect(analysis.measure(functions[0]).cyclomatic, 2);
    expect(analysis.measure(functions[1]).cyclomatic, 4);
    expect(analysis.measure(functions[2]).cyclomatic, 4);
  });

  test('includes JavaScript functions in shared complexity analysis', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-js-complexity-',
    );
    addTearDown(() => root.delete(recursive: true));
    File('${root.path}${Platform.pathSeparator}main.js').writeAsStringSync(
      sourceFixture(
        'javascript/includes_javascript_functions_in_shared_complexity_analysis/source.java',
      ),
    );

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(
      run.findings.map((Finding finding) => finding.code),
      contains('complex-function'),
    );
  });

  test(
    'runner discovers JavaScript-family files and preserves reachability',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-js-',
      );
      addTearDown(() => root.delete(recursive: true));
      File(
        '${root.path}${Platform.pathSeparator}main.js',
      ).writeAsStringSync("import './worker.js';\n");
      File(
        '${root.path}${Platform.pathSeparator}worker.js',
      ).writeAsStringSync('export const work = () => 1;\n');

      final AnalysisRun run = AnalysisRunner().run(
        CodeBusterCliContract.parse(<String>[
          'dead',
          '--root',
          root.path,
          '--lang',
          'javascript',
        ]),
      );

      expect(
        run.files.map((SourceFile file) => file.language),
        everyElement('javascript'),
      );
      expect(run.graph.dependenciesOf('main.js'), <String>['worker.js']);
      expect(
        run.findings.where((Finding finding) => finding.code == 'dead-file'),
        isEmpty,
      );
    },
  );
}
