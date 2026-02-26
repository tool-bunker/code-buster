import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  const RepositoryAnalysis repository = RepositoryAnalysis();

  test('calculates complexity and function-length findings', () {
    const FunctionSource function = FunctionSource(
      path: 'lib/logic.dart',
      name: 'logic',
      line: 3,
      source: '''
void logic() {
  if (first && second) {
    for (final item in items) {
      if (item.ready) {
        save(item);
      }
    }
  }
}
''',
    );
    const AnalysisConfig config = AnalysisConfig(
      root: '/project',
      complexityThreshold: 3,
      cognitiveThreshold: 4,
      maxFunctionLines: 5,
    );

    final List<Finding> findings = repository.complexityFindings(
      functions: <FunctionSource>[function],
      config: config,
    );

    expect(findings.map((Finding finding) => finding.code), <String>[
      'complex-function',
      'long-function',
    ]);
    expect(repository.measure(function).cyclomatic, 5);
  });

  test('ignores control-flow syntax and braces inside comments', () {
    const FunctionSource function = FunctionSource(
      path: 'src/style.cpp',
      name: 'Style',
      line: 1,
      source: '''
Style::Style() {
  Value = 1; // Set the value if the feature is active.
  /* Example:
     for (Item item : items) {
       if (item.ready && item.visible) {
       }
     }
  */
}
''',
    );

    final FunctionMetrics metrics = repository.measure(function);

    expect(metrics.cyclomatic, 1);
    expect(metrics.cognitive, 0);
  });

  test(
    'ignores Dart triple-quoted script control flow but counts Dart code',
    () {
      const FunctionSource tripleDoubleQuoted = FunctionSource(
        path: 'lib/webview.dart',
        name: 'injectDoubleQuoted',
        line: 1,
        source: r'''
void injectDoubleQuoted() {
  // A triple quote in a comment must not start a string: """
  const script = r"""
    if (remoteEnabled) {
      while (window.active) {
        poll();
      }
    }
  """;
  if (nativeEnabled) {
    inject(script);
  }
}
''',
      );
      const FunctionSource tripleSingleQuoted = FunctionSource(
        path: 'lib/webview.dart',
        name: 'injectSingleQuoted',
        line: 1,
        source: r"""
void injectSingleQuoted() {
  const script = r'''
    for (const item of items) {
      if (item.ready) {
        render(item);
      }
    }
  ''';
  for (final handler in nativeHandlers) {
    register(handler, script);
  }
}
""",
      );

      final FunctionMetrics doubleMetrics = repository.measure(
        tripleDoubleQuoted,
      );
      final FunctionMetrics singleMetrics = repository.measure(
        tripleSingleQuoted,
      );

      expect(doubleMetrics.cyclomatic, 2);
      expect(doubleMetrics.cognitive, 1);
      expect(singleMetrics.cyclomatic, 2);
      expect(singleMetrics.cognitive, 1);
    },
  );

  test('ignores commented gotos without letting strings hide real gotos', () {
    final List<Finding> findings = repository.fileFindings(
      sources: <String, String>{
        'src/example.c': '''
/*
 * Example cleanup:
 * goto out;
 */
int example(void) {
  // goto ignored;
  const char* marker = "/*";
  goto cleanup;
cleanup:
  return 0;
}
''',
      },
      config: const AnalysisConfig(root: '/project'),
    );

    final Finding finding = findings.singleWhere(
      (Finding finding) => finding.code == 'goto-statement',
    );
    expect(finding.line, 8);
    expect(
      finding.message,
      'use of goto makes control flow hard to review and analyze',
    );
  });

  test('leaves C++ goto reporting to the language rule', () {
    final List<Finding> findings = repository.fileFindings(
      sources: const <String, String>{
        'src/example.c': 'goto cleanup;\n',
        'src/example.h': 'goto cleanup;\n',
        'src/example.cpp': 'goto cleanup;\n',
      },
      config: const AnalysisConfig(root: '/project'),
    );

    expect(
      findings
          .where((Finding finding) => finding.code == 'goto-statement')
          .map((Finding finding) => finding.path),
      <String>['src/example.c', 'src/example.h'],
    );
  });

  test('enforces configured source layout policy', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-structure-',
    );
    addTearDown(() => root.delete(recursive: true));
    Directory(path.join(root.path, 'lib')).createSync();
    final List<SourceFile> files = <SourceFile>[
      SourceFile(
        absolutePath: path.join(root.path, 'lib', 'a.dart'),
        relativePath: 'lib/a.dart',
        language: 'dart',
      ),
      SourceFile(
        absolutePath: path.join(root.path, 'lib', 'b.dart'),
        relativePath: 'lib/b.dart',
        language: 'dart',
      ),
    ];

    final List<Finding> findings = repository.structureFindings(
      files: files,
      config: AnalysisConfig(
        root: root.path,
        structureSourceRoots: const <String>['lib'],
        structureMaxTopLevelFiles: 1,
        structureRequiredDirectories: const <String>['features'],
      ),
    );

    expect(findings.map((Finding finding) => finding.code), <String>[
      'structure-missing-required-dir',
      'structure-top-level-file',
    ]);
  });

  test(
    'finds feature flags but excludes string literals and collection APIs',
    () {
      final List<Finding> findings = FeatureFlagAnalysis()
          .findings(<String, String>{
            'lib/flags.dart': '''
final first = Flags.featureNewCheckout;
final duplicate = Flags.featureNewCheckout;
final text = "Flags.notAFlag";
final contains = Config.Contains;
final collection = Config.push;
final enabled = Config.featureEnabled;
final other = flags.beta;
final semantics = flags.isChecked;
final geometry = flags.appliesStyle;
''',
          });

      expect(findings.map((Finding finding) => finding.message), <String>[
        'feature flag reference: featureNewCheckout',
        'feature flag reference: featureEnabled',
        'feature flag reference: beta',
      ]);
    },
  );

  test('reports generic parameters without visible use', () {
    final List<Finding> findings = YagniAnalysis().unusedGenericParameters(
      const <GenericDeclaration>[
        GenericDeclaration(
          path: 'lib/cache.dart',
          name: 'Cache',
          line: 1,
          endLine: 4,
          parameters: <String>['T', 'Unused'],
          declaration: 'class Cache<T, Unused>',
          usageSource: 'class Cache { final T value; }',
        ),
      ],
    );

    expect(
      findings.single.message,
      "generic parameter 'Unused' is not used by Cache",
    );
  });

  test('aggregates Git numstat churn and ranks known files', () {
    final List<Hotspot> hotspots = HotspotAnalysis.parseNumstat(
      '__CODE_BUSTER_COMMIT__\n10\t2\tlib/a.dart\n3\t1\tlib/a.dart\n4\t0\tlib/b.dart\n'
      '__CODE_BUSTER_COMMIT__\n5\t5\tlib/a.dart\n-\t-\tassets/image.png\n',
      allowed: const <String>{'lib/a.dart', 'lib/b.dart'},
    );

    expect(hotspots.first.path, 'lib/a.dart');
    expect(hotspots.first.commits, 2);
    expect(hotspots.first.added, 18);
    expect(hotspots.first.deleted, 8);
    expect(hotspots.first.churn, 26);
    expect(hotspots.last.path, 'lib/b.dart');
  });

  test('preserves configured exclusions when CLI exclusions are absent', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code-buster-config-exclude-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File(path.join(root.path, 'code-buster.toml')).writeAsStringSync('''
languages = ["dart"]
[files]
exclude = ["test"]
''');
    File(path.join(root.path, 'lib', 'main.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void main() {}\n');
    File(path.join(root.path, 'test', 'bad_test.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void test() {}\n');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(run.files.map((SourceFile file) => file.relativePath), <String>[
      'lib/main.dart',
    ]);
  });

  test('enforces report count and off modes at the runner boundary', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code-buster-rule-modes-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File(path.join(root.path, 'code-buster.toml')).writeAsStringSync('''
languages = ["dart"]
[rules.mode]
tab-indent = "report"
trailing-whitespace = "count"
feature-flag = "off"
''');
    File(path.join(root.path, 'main.dart')).writeAsStringSync(
      'const bool enableFeature = true;\nvoid main() {\n\tprint("debug");   \n}\n',
    );

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(
      run.findings.map((Finding finding) => finding.code),
      allOf(contains('tab-indent'), contains('trailing-whitespace')),
    );
    expect(
      run.findings.where((Finding finding) => finding.code == 'feature-flag'),
      isEmpty,
    );
    expect(
      run.actionableFindings.map((Finding finding) => finding.code),
      contains('tab-indent'),
    );
    expect(
      run.advisoryFindings.map((Finding finding) => finding.code),
      contains('trailing-whitespace'),
    );
  });

  test('collects hotspots from local Git history', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-hotspots-',
    );
    addTearDown(() => root.delete(recursive: true));
    _git(root, <String>['init']);
    _git(root, <String>['config', 'user.email', 'code-buster@example.test']);
    _git(root, <String>['config', 'user.name', 'Code Buster Test']);
    final File file = File(path.join(root.path, 'lib', 'hot.dart'));
    file.parent.createSync(recursive: true);
    file.writeAsStringSync('void hot() {}\n');
    _git(root, <String>['add', '.']);
    _git(root, <String>['commit', '-m', 'initial']);

    final List<Hotspot> hotspots = HotspotAnalysis.fromGit(
      root: root.path,
      allowed: const <String>{'lib/hot.dart'},
    );

    expect(hotspots.single.path, 'lib/hot.dart');
    expect(hotspots.single.commits, 1);
  });
}

void _git(Directory root, List<String> arguments) {
  final ProcessResult result = Process.runSync('git', <String>[
    '-C',
    root.path,
    ...arguments,
  ]);
  if (result.exitCode != 0) {
    throw StateError('git ${arguments.join(' ')} failed: ${result.stderr}');
  }
}
