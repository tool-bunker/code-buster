import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  test('applies finding controls and changed-line scope immutably', () {
    const Finding outside = Finding(
      code: 'demo',
      severity: RuleSeverity.warn,
      path: 'lib/main.dart',
      line: 1,
      message: 'outside',
    );
    const Finding changed = Finding(
      code: 'demo',
      severity: RuleSeverity.warn,
      path: 'lib/main.dart',
      line: 2,
      message: 'changed',
    );
    final PreparedAnalysis prepared = PreparedAnalysis(
      root: '/project',
      config: const AnalysisConfig(root: '/project', changedLines: true),
      files: const <SourceFile>[],
      sources: const <String, String>{'lib/main.dart': 'one\ntwo'},
      changedLineRanges: const <String, List<ChangedLineRange>>{
        'lib/main.dart': <ChangedLineRange>[ChangedLineRange(2, 2)],
      },
    );

    final List<Finding> findings = const FindingControlStage().apply(
      prepared: prepared,
      findings: const <Finding>[outside, changed],
      baseline: const <String>{},
      only: 'demo',
    );

    expect(findings, <Finding>[changed]);
    expect(() => findings.add(outside), throwsUnsupportedError);
  });

  test('prepares immutable configured and language-indexed sources', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code-buster-pipeline-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File(
      path.join(root.path, 'pubspec.yaml'),
    ).writeAsStringSync('name: pipeline_fixture\n');
    File(path.join(root.path, 'lib', 'main.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void main() {}\n');
    File(path.join(root.path, 'tool', 'helper.py'))
      ..createSync(recursive: true)
      ..writeAsStringSync('def helper():\n    pass\n');
    File(path.join(root.path, 'web', 'main.js'))
      ..createSync(recursive: true)
      ..writeAsStringSync("import './helper.js';\n");
    File(path.join(root.path, 'web', 'helper.js'))
      ..createSync(recursive: true)
      ..writeAsStringSync('export const value = 1;\n');
    File(path.join(root.path, 'test', 'ignored.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void ignored() {}\n');
    File(path.join(root.path, 'code-buster.toml')).writeAsStringSync('''
languages = ["auto"]
[files]
exclude = ["test"]
''');

    final PreparedAnalysis prepared = AnalysisPreparationStage().prepare(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(
      prepared.config.languages,
      containsAll(<String>['dart', 'javascript']),
    );
    expect(prepared.sources.keys, <String>[
      'lib/main.dart',
      'tool/helper.py',
      'web/helper.js',
      'web/main.js',
    ]);
    expect(prepared.sourcesFor(<String>{'python'}).keys, <String>[
      'tool/helper.py',
    ]);
    expect(
      GraphConstructionStage(LanguagePluginRegistry.standard())
          .build(
            LanguageIndexStage(
              LanguagePluginRegistry.standard(),
            ).build(prepared),
          )
          .dependenciesOf('web/main.js'),
      <String>['web/helper.js'],
    );
    expect(() => prepared.sources['other.dart'] = '', throwsUnsupportedError);
  });

  test('decodes BOM-marked UTF-16 source without a processing warning', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-utf16-');
    addTearDown(() => root.deleteSync(recursive: true));
    final List<int> bytes = <int>[0xff, 0xfe];
    for (final int unit in 'const value = 1;\n'.codeUnits) {
      bytes
        ..add(unit & 0xff)
        ..add(unit >> 8);
    }
    File(path.join(root.path, 'legacy.js')).writeAsBytesSync(bytes);

    final PreparedAnalysis prepared = AnalysisPreparationStage().prepare(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(prepared.sources['legacy.js'], 'const value = 1;\n');
    expect(prepared.coverage['malformed_encoding'], isNull);
    expect(prepared.diagnostics, isEmpty);
  });

  test(
    'decodes malformed UTF-8 source without aborting the repository run',
    () {
      final Directory root = Directory.systemTemp.createTempSync(
        'cb-encoding-',
      );
      addTearDown(() => root.deleteSync(recursive: true));
      File(path.join(root.path, 'legacy.js')).writeAsBytesSync(<int>[
        ...'const label = "'.codeUnits,
        0x96,
        ...'";\n'.codeUnits,
      ]);

      final PreparedAnalysis prepared = AnalysisPreparationStage().prepare(
        CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
      );

      expect(prepared.sources['legacy.js'], contains('\uFFFD'));
      expect(prepared.coverage['malformed_encoding'], 1);
    },
  );

  test('uses production classification by default and --all overrides it', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-scope-');
    addTearDown(() => root.deleteSync(recursive: true));
    for (final String relative in <String>[
      'lib/main.dart',
      'test/main_test.dart',
      'example/demo.dart',
    ]) {
      File(path.join(root.path, relative))
        ..createSync(recursive: true)
        ..writeAsStringSync('void main() {}\n');
    }
    File(
      path.join(root.path, 'pubspec.yaml'),
    ).writeAsStringSync('name: demo\n');

    PreparedAnalysis prepare(List<String> extra) =>
        AnalysisPreparationStage().prepare(
          CodeBusterCliContract.parse(<String>[
            'summary',
            '--root',
            root.path,
            ...extra,
          ]),
        );

    final PreparedAnalysis production = prepare(const <String>[]);
    expect(production.sources.keys, <String>['lib/main.dart']);
    expect(production.coverage, <String, int>{
      'example': 1,
      'selected': 1,
      'test': 1,
    });
    expect(prepare(const <String>['--include-tests']).sources.keys, <String>[
      'lib/main.dart',
      'test/main_test.dart',
    ]);
    expect(prepare(const <String>['--include-examples']).sources.keys, <String>[
      'example/demo.dart',
      'lib/main.dart',
    ]);
    expect(prepare(const <String>['--all']).sources.keys, <String>[
      'example/demo.dart',
      'lib/main.dart',
      'test/main_test.dart',
    ]);
  });
}
