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

  test('resolves imported package submodules before package initializers', () {
    final DependencyGraph graph = PythonGraphAdapter().build(<String, String>{
      'fastapi/__init__.py': 'from fastapi import routing\n',
      'fastapi/routing.py': '''
"""
Example:
    from fastapi import FastAPI
"""
''',
    });

    expect(graph.dependenciesOf('fastapi/__init__.py'), <String>[
      'fastapi/routing.py',
    ]);
    expect(
      graph.dependenciesOf('fastapi/routing.py'),
      isEmpty,
      reason: 'imports in docstrings are documentation, not graph edges',
    );
  });

  test('excludes TYPE_CHECKING-only imports from runtime graph edges', () {
    final DependencyGraph graph = PythonGraphAdapter().build(<String, String>{
      'app/models.py': '''
from typing import TYPE_CHECKING
import app.runtime

if TYPE_CHECKING:
    from app import controller

if typing.TYPE_CHECKING:
    import app.views

def load_lazily():
    import app.lazy
''',
      'app/runtime.py': '',
      'app/controller.py': '',
      'app/views.py': '',
      'app/lazy.py': '',
    });

    expect(graph.dependenciesOf('app/models.py'), <String>['app/runtime.py']);
  });

  test('shares indexed source facts across Python analysis products', () {
    final LanguageAnalysis analysis = PythonLanguagePlugin().analyze(
      const <String, String>{
        'app/main.py':
            'from . import worker\n\ndef load():\n    return open("data.txt")\n',
        'app/worker.py': 'def work():\n    return 1\n',
      },
      const AnalysisConfig(
        root: '/project',
        severityOverrides: <String, RuleSeverity>{
          'py-open-no-encoding': RuleSeverity.info,
        },
      ),
    );

    expect(analysis.graph.dependenciesOf('app/main.py'), <String>[
      'app/worker.py',
    ]);
    expect(
      analysis.functions.map((FunctionSource function) => function.name),
      <String>['load', 'work'],
    );
    expect(
      analysis.findings.map((Finding finding) => finding.code),
      contains('py-open-no-encoding'),
    );
  });

  test('treats public packages and executable scripts as Python roots', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-python-library-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory package = Directory(
      '${root.path}${Platform.pathSeparator}src${Platform.pathSeparator}library',
    )..createSync(recursive: true);
    File(
      '${package.path}${Platform.pathSeparator}__init__.py',
    ).writeAsStringSync('from . import api\n');
    File(
      '${package.path}${Platform.pathSeparator}api.py',
    ).writeAsStringSync('def load():\n    return 1\n');
    final Directory tools = Directory(
      '${root.path}${Platform.pathSeparator}tools',
    )..createSync();
    File(
      '${tools.path}${Platform.pathSeparator}generate.py',
    ).writeAsStringSync('if __name__ == "__main__":\n    print("generate")\n');

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
      run.findings.where((Finding finding) => finding.code == 'dead-file'),
      isEmpty,
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
    File(
      '${app.path}${Platform.pathSeparator}dormant.py',
    ).writeAsStringSync('def unused():\n    return 1\n');

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
      run.findings
          .where((Finding finding) => finding.code == 'dead-file')
          .map((Finding finding) => finding.path),
      <String>['app/dormant.py'],
    );
  });
}
