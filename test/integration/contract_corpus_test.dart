import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/cli_process.dart';

void main() {
  const String root = 'test/fixtures/contract_corpus/dart_project';

  test('Dart contract corpus exercises wired summary rule families', () {
    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root]),
    );
    final Set<String> codes = run.findings
        .map((Finding finding) => finding.code)
        .toSet();

    expect(run.config.language, 'dart');
    expect(run.languageSummary['dart']?['files'], 4);
    expect(run.languageSummary['dart']?['findings'], greaterThan(0));
    expect(
      run.languageSummary['dart']?['findings'],
      lessThanOrEqualTo(run.findings.length),
    );
    expect(
      run.files.map((SourceFile file) => file.relativePath),
      orderedEquals(<String>[
        'lib/a.dart',
        'lib/b.dart',
        'lib/main.dart',
        'lib/orphan.dart',
      ]),
    );
    expect(
      codes,
      containsAll(<String>[
        'duplicate-block',
        'feature-flag',
        'structure-missing-required-dir',
        'repeated-condition',
        'structure-top-level-file',
      ]),
    );
  });

  test('auto-detects substantial languages in registry order', () async {
    final Directory project = await Directory.systemTemp.createTemp(
      'code-buster-auto-',
    );
    addTearDown(() => project.delete(recursive: true));
    Directory('${project.path}/lib').createSync();
    File('${project.path}/lib/a.dart').writeAsStringSync('void a() {}');
    File('${project.path}/lib/b.dart').writeAsStringSync('void b() {}');
    File('${project.path}/one.py').writeAsStringSync('def one(): pass');
    File('${project.path}/two.py').writeAsStringSync('def two(): pass');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', project.path]),
    );

    expect(run.config.languages, <String>['dart', 'python']);
    expect(run.languageSummary.keys, containsAll(<String>['dart', 'python']));
  });

  test('implemented analysis commands accept the contract corpus', () {
    final List<CodeBusterCommand> commands = <CodeBusterCommand>[
      CodeBusterCommand.summary,
      CodeBusterCommand.dead,
      CodeBusterCommand.duplication,
      CodeBusterCommand.structure,
      CodeBusterCommand.clusters,
      CodeBusterCommand.complexity,
      CodeBusterCommand.flags,
      CodeBusterCommand.review,
      CodeBusterCommand.pr,
      CodeBusterCommand.test,
    ];
    for (final CodeBusterCommand command in commands) {
      final AnalysisRun run = AnalysisRunner().run(
        CodeBusterCliContract.parse(<String>[command.name, '--root', root]),
      );
      expect(run.files, isNotEmpty, reason: command.name);
    }
  });

  test('CLI emits stable JSON envelopes for the contract corpus', () async {
    Future<ProcessResult> runCli(String command) => runCodeBuster(<String>[
      command,
      '--root',
      root,
      '--format',
      'json',
    ], workingDirectory: Directory.current.path);

    final ProcessResult summary = await runCli('summary');
    final ProcessResult graph = await runCli('graph');
    final ProcessResult complexity = await runCli('complexity');
    final ProcessResult flags = await runCli('flags');
    final ProcessResult duplication = await runCli('duplication');
    final ProcessResult dead = await runCli('dead');
    final ProcessResult structure = await runCli('structure');
    final ProcessResult review = await runCli('review');
    final ProcessResult quality = await runCli('quality');
    final ProcessResult doctor = await runCli('doctor');
    final ProcessResult actions = await runCli('actions');
    final ProcessResult repeatedSummary = await runCli('summary');

    expect(
      <ProcessResult>[
        summary,
        graph,
        complexity,
        flags,
        duplication,
        dead,
        structure,
        review,
        quality,
        doctor,
        actions,
        repeatedSummary,
      ].every((ProcessResult item) => item.exitCode == 0),
      isTrue,
    );
    expect(
      summary.stdout,
      allOf(contains('"command":"summary"'), contains('duplicate-block')),
    );
    expect(repeatedSummary.stdout, summary.stdout);
    expect(
      graph.stdout,
      allOf(contains('"command":"graph"'), contains('"source":"lib/a.dart"')),
    );
    expect(
      complexity.stdout,
      allOf(contains('"command":"complexity"'), contains('complex-function')),
    );
    expect(flags.stdout, contains('feature-flag'));
    expect(
      duplication.stdout,
      allOf(contains('duplicate-block'), contains('repeated-condition')),
    );
    expect(dead.stdout, contains('"command":"dead"'));
    expect(structure.stdout, contains('structure-missing-required-dir'));
    expect(review.stdout, contains('"command":"review"'));
    expect(quality.stdout, contains('"command":"quality"'));
    expect(doctor.stdout, contains('Code Buster doctor'));
    expect(actions.stdout, contains('"command":"actions"'));
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('fixture is immutable during analysis', () {
    final File source = File('$root/lib/main.dart');
    final String before = source.readAsStringSync();
    AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root]),
    );
    expect(source.readAsStringSync(), before);
  });
}
