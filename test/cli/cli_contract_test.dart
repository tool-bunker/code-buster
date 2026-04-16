import 'package:args/command_runner.dart';
import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('parses documented global options and a target', () {
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(<String>[
      'inspect',
      '--root',
      '/project',
      '--language',
      'dart',
      '--languages=dart,typescript',
      '--include',
      'lib',
      '--exclude',
      'generated',
      '--top',
      '5',
      '--format',
      'sarif',
      '--changed-lines',
      '--ci',
      'lib/main.dart',
    ]);

    expect(options.command, CodeBusterCommand.inspect);
    expect(options.root, '/project');
    expect(options.language, 'dart');
    expect(options.languages, <String>['dart', 'typescript']);
    expect(options.includes, <String>['lib']);
    expect(options.excludes, <String>['generated']);
    expect(options.top, 5);
    expect(options.format, ReportFormat.sarif);
    expect(options.changedBase, '');
    expect(options.changedLines, isTrue);
    expect(options.ci, isTrue);
    expect(options.failOnIssues, isTrue);
    expect(options.target, 'lib/main.dart');
  });

  test('preserves both positional targets for dependency paths', () {
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(<String>[
      'path',
      'lib/a.dart',
      'lib/b.dart',
    ]);

    expect(options.command, CodeBusterCommand.path);
    expect(options.targets, <String>['lib/a.dart', 'lib/b.dart']);
    expect(options.target, 'lib/a.dart');
  });

  test('defaults to summary and maps changed to HEAD', () {
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(<String>[
      '--changed',
    ]);

    expect(options.command, CodeBusterCommand.summary);
    expect(options.changedBase, 'HEAD');
    expect(options.includeAll, isFalse);
    expect(options.format, ReportFormat.text);
  });

  test('pr defaults changed repositories to changed-line gating', () {
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(<String>[
      'pr',
      '--changed-base',
      'origin/main',
    ]);

    expect(options.changedBase, 'origin/main');
    expect(options.changedLines, isTrue);
  });

  test('parses the all-sources override', () {
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(<String>[
      'summary',
      '--all',
    ]);

    expect(options.includeAll, isTrue);
  });

  test('rejects unknown commands and invalid report formats', () {
    expect(
      () => CodeBusterCliContract.parse(<String>['unknown']),
      throwsA(isA<UsageException>()),
    );
    expect(
      () =>
          CodeBusterCliContract.parse(<String>['summary', '--format', 'yaml']),
      throwsFormatException,
    );
  });

  test('generates shell completion contracts', () {
    expect(
      CodeBusterCliContract.completions('bash'),
      contains('summary graph dead'),
    );
    expect(
      CodeBusterCliContract.completions('fish'),
      contains('complete -c cb'),
    );
    expect(CodeBusterCliContract.completions('zsh'), contains('#compdef cb'));
  });
}
