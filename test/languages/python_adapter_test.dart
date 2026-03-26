import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('resolves local absolute and relative Python imports', () {
    final DependencyGraph graph = PythonGraphAdapter().build(<String, String>{
      'app/main.py': 'from . import worker\nimport app.tools.helper\n',
      'app/worker.py': '',
      'app/tools/helper.py': '',
    });

    expect(
      graph.dependenciesOf('app/main.py'),
      orderedEquals(<String>['app/tools/helper.py', 'app/worker.py']),
    );
  });

  test('extracts indentation-scoped Python functions', () {
    final List<FunctionSource> functions = PythonFunctionParser()
        .parse(<String, String>{
          'app/worker.py':
              'async def work(value):\n'
              '    if value:\n'
              '        return value\n'
              '\n'
              'def helper():\n'
              '    return 1\n',
        });

    expect(functions.map((FunctionSource item) => item.name), <String>[
      'work',
      'helper',
    ]);
    expect(functions.first.source, contains('return value'));
    expect(functions.first.source, isNot(contains('def helper')));
  });

  test('runner discovers Python and preserves local reachability', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-python-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory app = Directory('${root.path}${Platform.pathSeparator}app')
      ..createSync();
    File(
      '${app.path}${Platform.pathSeparator}main.py',
    ).writeAsStringSync('from . import worker\n');
    File(
      '${app.path}${Platform.pathSeparator}worker.py',
    ).writeAsStringSync('def work():\n    return 1\n');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>[
        'dead',
        '--root',
        root.path,
        '--lang',
        'python',
      ]),
    );
    expect(
      run.files.map((SourceFile file) => file.language),
      everyElement('python'),
    );
    expect(run.graph.dependenciesOf('app/main.py'), <String>['app/worker.py']);
    expect(
      run.findings.where((Finding finding) => finding.code == 'dead-file'),
      isEmpty,
    );
  });
}
