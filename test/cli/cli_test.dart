import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import '../support/cli_process.dart';

void main() {
  test('version reports the Code Buster runtime', () async {
    final ProcessResult result = await runCodeBuster(<String>[
      '--version',
    ], workingDirectory: Directory.current.path);

    expect(result.exitCode, 0);
    expect(result.stdout, 'cb 0.2.0\nruntime: Dart\n');
    expect(result.stderr, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('completions command emits the requested shell contract', () async {
    final ProcessResult result = await runCodeBuster(<String>[
      'completions',
      'bash',
    ], workingDirectory: Directory.current.path);

    expect(result.exitCode, 0);
    expect(result.stdout, contains('complete -W "summary graph dead'));
    expect(result.stderr, isEmpty);
  });

  test('rules lists effective semantic modes and inactive reasons', () async {
    final ProcessResult result = await runCodeBuster(<String>[
      'rules',
      '--root',
      '.',
      '--format=json',
    ], workingDirectory: Directory.current.path);
    final Map<String, dynamic> report =
        jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final List<Map<String, dynamic>> rules = (report['rules'] as List<dynamic>)
        .cast<Map<String, dynamic>>();
    final Map<String, dynamic> promptRule = rules.singleWhere(
      (Map<String, dynamic> rule) =>
          rule['id'] == 'ai-prompt-injection-instruction',
    );

    expect(result.exitCode, 0);
    expect(promptRule['group'], 'security');
    expect(promptRule['mode'], 'report');
    expect(result.stderr, isEmpty);
  });

  test('summary analyzes a Dart project and emits JSON findings', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-cli-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory lib = Directory('${root.path}${Platform.pathSeparator}lib')
      ..createSync();
    File(
      '${lib.path}${Platform.pathSeparator}main.dart',
    ).writeAsStringSync('void main() {\n\tprint("debug");\n}\n');

    final ProcessResult result = await runCodeBuster(<String>[
      'summary',
      '--root',
      root.path,
      '--format',
      'json',
    ], workingDirectory: Directory.current.path);
    final ProcessResult advisory = await runCodeBuster(<String>[
      'review',
      '--root',
      root.path,
      '--advisory',
      '--format',
      'json',
    ], workingDirectory: Directory.current.path);
    final Map<String, dynamic> summary =
        jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final Map<String, dynamic> advisoryReport =
        jsonDecode(advisory.stdout as String) as Map<String, dynamic>;

    expect(result.exitCode, 0);
    expect(summary['command'], 'summary');
    expect(summary['actionableFindingCount'], 0);
    expect(
      (summary['advisorySummary'] as Map<String, dynamic>)['total'],
      greaterThan(0),
    );
    expect(advisoryReport['findings'], isNotEmpty);
    expect(advisory.stdout, contains('tab-indent'));
    expect(result.stderr, isEmpty);
    expect(advisory.stderr, isEmpty);
  });

  test(
    'init writes the starter config and refuses an accidental overwrite',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-init-',
      );
      addTearDown(() => root.delete(recursive: true));
      final List<String> command = <String>['init', '--root', root.path];

      final ProcessResult first = await runCodeBuster(
        command,
        workingDirectory: Directory.current.path,
      );
      final ProcessResult second = await runCodeBuster(
        command,
        workingDirectory: Directory.current.path,
      );

      expect(first.exitCode, 0);
      expect(
        File(
          '${root.path}${Platform.pathSeparator}code-buster.toml',
        ).existsSync(),
        isTrue,
      );
      expect(second.exitCode, 1);
      expect(second.stderr, contains('config exists'));
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test(
    'config and baseline commands operate on the selected project root',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-operations-',
      );
      addTearDown(() => root.delete(recursive: true));
      final Directory lib = Directory(
        '${root.path}${Platform.pathSeparator}lib',
      )..createSync();
      File(
        '${lib.path}${Platform.pathSeparator}main.dart',
      ).writeAsStringSync('void main() {\n\tprint("debug");\n}\n');
      final File baseline = File(
        '${root.path}${Platform.pathSeparator}findings.json',
      );

      final ProcessResult config = await runCodeBuster(<String>[
        'config',
        '--root',
        root.path,
        '--format',
        'json',
      ], workingDirectory: Directory.current.path);
      final ProcessResult baselineResult = await runCodeBuster(<String>[
        'baseline',
        '--root',
        root.path,
        '--output',
        baseline.path,
      ], workingDirectory: Directory.current.path);

      expect(config.exitCode, 0);
      expect(config.stdout, contains('"root":"${root.path}"'));
      expect(baselineResult.exitCode, 0);
      expect(baseline.existsSync(), isTrue);
      expect(baseline.readAsStringSync(), contains('tab-indent'));

      final ProcessResult stats = await runCodeBuster(<String>[
        'baseline',
        'stats',
        '--root',
        root.path,
        '--output',
        baseline.path,
      ], workingDirectory: Directory.current.path);
      expect(stats.exitCode, 0);
      expect(stats.stdout, contains('"command":"baseline stats"'));
      expect(stats.stdout, contains('"stale":0'));
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'uses Code Buster exit codes for invalid commands and CI findings',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-exit-',
      );
      addTearDown(() => root.delete(recursive: true));
      final Directory lib = Directory(
        '${root.path}${Platform.pathSeparator}lib',
      )..createSync();
      File(
        '${lib.path}${Platform.pathSeparator}main.dart',
      ).writeAsStringSync('void main() {\n\tprint("debug");\n}\n');

      final ProcessResult invalid = await runCodeBuster(<String>[
        'unknown',
      ], workingDirectory: Directory.current.path);
      final ProcessResult ci = await runCodeBuster(<String>[
        'summary',
        '--root',
        root.path,
        '--ci',
      ], workingDirectory: Directory.current.path);
      File(
        '${root.path}${Platform.pathSeparator}code-buster.toml',
      ).writeAsStringSync('[rules.mode]\ntab-indent = "report"\n');
      final ProcessResult configuredCi = await runCodeBuster(<String>[
        'summary',
        '--root',
        root.path,
        '--ci',
      ], workingDirectory: Directory.current.path);

      expect(invalid.exitCode, 2);
      expect(invalid.stderr, contains('Unknown Code Buster command'));
      expect(ci.exitCode, 0);
      expect(configuredCi.exitCode, 2);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test('operational commands expose repository views', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-views-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory lib = Directory('${root.path}${Platform.pathSeparator}lib')
      ..createSync();
    File('${lib.path}${Platform.pathSeparator}main.dart').writeAsStringSync(
      "import 'other.dart';\nvoid main() {\n\tprint('debug');\n}\nvoid _helper() {}\n",
    );
    File(
      '${lib.path}${Platform.pathSeparator}other.dart',
    ).writeAsStringSync("import 'main.dart';\n");

    Future<ProcessResult> runCli(List<String> arguments) => runCodeBuster(
      <String>[...arguments, '--root', root.path],
      workingDirectory: Directory.current.path,
    );

    final ProcessResult doctor = await runCli(<String>[
      'doctor',
      '--format',
      'json',
    ]);
    final ProcessResult score = await runCli(<String>[
      'score',
      '--format',
      'json',
    ]);
    final ProcessResult quality = await runCli(<String>[
      'quality',
      '--format',
      'json',
    ]);
    final ProcessResult actions = await runCli(<String>['actions']);
    final ProcessResult inspect = await runCli(<String>[
      'inspect',
      'lib/main.dart',
      '--format',
      'json',
    ]);
    final ProcessResult related = await runCli(<String>[
      'related',
      'lib/main.dart',
      '--format',
      'json',
    ]);
    final ProcessResult explain = await runCli(<String>[
      'explain',
      'dart-print',
    ]);

    expect(
      <ProcessResult>[
        doctor,
        score,
        quality,
        actions,
        inspect,
        related,
        explain,
      ].every((ProcessResult result) => result.exitCode == 0),
      isTrue,
    );
    expect(doctor.stdout, contains('Code Buster doctor'));
    expect(score.stdout, contains('Code Buster score:'));
    expect(quality.stdout, contains('"debt_minutes"'));
    expect(quality.stdout, contains('"measureSchemaVersion":1'));
    expect(quality.stdout, contains('"gate_conditions"'));
    expect(quality.stdout, contains('"modules"'));
    expect(actions.stdout, contains('"actions"'));
    expect(inspect.stdout, contains('tab-indent'));
    final Map<String, dynamic> inspected =
        jsonDecode(inspect.stdout as String) as Map<String, dynamic>;
    expect(inspected['imports'], <Object>['other.dart']);
    expect(inspected['exports'], <Object>['main']);
    expect(inspected['functions'], <Object>[
      <String, Object>{'name': 'main', 'line': 2},
      <String, Object>{'name': '_helper', 'line': 5},
    ]);
    expect(related.stdout, contains('lib/other.dart'));
    expect(explain.stdout, contains('dart-print'));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('fix previews and applies only safe whitespace changes', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-cli-fix-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory lib = Directory('${root.path}${Platform.pathSeparator}lib')
      ..createSync();
    final File source = File('${lib.path}${Platform.pathSeparator}main.dart')
      ..writeAsStringSync('\tvoid main() { print("left\\tmiddle"); }  \n');
    final List<String> base = <String>['fix', '--root', root.path];

    final ProcessResult preview = await runCodeBuster(<String>[
      ...base,
      '--dry-run',
    ], workingDirectory: Directory.current.path);
    expect(preview.exitCode, 0);
    expect(preview.stdout, contains('would fix lib/main.dart'));
    expect(
      source.readAsStringSync(),
      '\tvoid main() { print("left\\tmiddle"); }  \n',
    );

    final ProcessResult applied = await runCodeBuster(
      base,
      workingDirectory: Directory.current.path,
    );
    expect(applied.exitCode, 0);
    expect(applied.stdout, contains('fixed lib/main.dart'));
    expect(
      source.readAsStringSync(),
      '  void main() { print("left\\tmiddle"); }\n',
    );
  });
}
