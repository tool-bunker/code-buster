// Command names and global flags are a compatibility surface, so they are defined once instead of being rediscovered by handlers.

import 'package:args/args.dart';
import 'package:args/command_runner.dart';

import '../reporting/reporting.dart';

/// Stable Code Buster command names used by parsing, handlers, and contracts.
enum CodeBusterCommand {
  summary,
  graph,
  dead,
  duplication,
  structure,
  clusters,
  complexity,
  flags,
  hotspots,
  inspect,
  related,
  why,
  path,
  score,
  quality,
  plan,
  actions,
  review,
  pr,
  doctor,
  preview,
  explain,
  rules,
  config,
  baseline,
  fix,
  init,
  test,
  version,
  update,
  completions;

  static CodeBusterCommand parse(String value) {
    for (final CodeBusterCommand command in CodeBusterCommand.values) {
      if (command.name == value) {
        return command;
      }
    }
    throw UsageException(
      'Unknown Code Buster command: $value',
      CodeBusterCliContract.parser.usage,
    );
  }
}

/// Fully parsed global Code Buster CLI options and positional target.
final class CodeBusterCliOptions {
  const CodeBusterCliOptions({
    required this.command,
    required this.root,
    required this.language,
    required this.languages,
    required this.top,
    required this.format,
    required this.includes,
    required this.excludes,
    required this.only,
    required this.baseline,
    this.ingestSarif = const <String>[],
    required this.output,
    required this.changedBase,
    required this.changedLines,
    required this.failOnIssues,
    required this.verbose,
    required this.ci,
    required this.allowEmpty,
    this.includeAll = false,
    this.includeAdvisory = false,
    this.allFindings = false,
    this.findingGroup = '',
    this.inactiveRules = false,
    this.includeTests = false,
    this.includeExamples = false,
    this.includeVendored = false,
    required this.force,
    required this.dryRun,
    required this.targets,
  });

  final CodeBusterCommand command;
  final String root;
  final String language;
  final List<String> languages;
  final int top;
  final ReportFormat format;
  final List<String> includes;
  final List<String> excludes;
  final String only;
  final String baseline;
  final List<String> ingestSarif;
  final String output;
  final String changedBase;
  final bool changedLines;
  final bool failOnIssues;
  final bool verbose;
  final bool ci;
  final bool allowEmpty;
  final bool includeAdvisory;
  final bool allFindings;
  final String findingGroup;
  final bool inactiveRules;
  final bool includeAll;
  final bool includeTests;
  final bool includeExamples;
  final bool includeVendored;
  final bool force;
  final bool dryRun;
  final List<String> targets;

  String? get target => targets.firstOrNull;
}

/// Parses Code Buster's documented global option contract independently of handlers.
final class CodeBusterCliContract {
  CodeBusterCliContract._();

  static final ArgParser parser = ArgParser(allowTrailingOptions: true)
    ..addOption('root', abbr: 'r', defaultsTo: '.')
    ..addOption('lang', abbr: 'l')
    ..addOption('language')
    ..addMultiOption('languages', valueHelp: 'LANG,LANG')
    ..addOption('top', abbr: 'n', defaultsTo: '0')
    ..addOption('format', defaultsTo: 'text')
    ..addMultiOption('include')
    ..addMultiOption('exclude')
    ..addOption('only')
    ..addOption('baseline')
    ..addMultiOption('ingest-sarif')
    ..addOption('output')
    ..addOption('changed-base')
    ..addFlag('changed', negatable: false)
    ..addFlag('changed-lines', negatable: false)
    ..addFlag('fail-on-issues', negatable: false)
    ..addFlag('verbose', negatable: false)
    ..addFlag('ci', negatable: false)
    ..addFlag('allow-empty', negatable: false)
    ..addFlag('all', negatable: false)
    ..addFlag('advisory', negatable: false)
    ..addFlag('all-findings', negatable: false)
    ..addOption('group')
    ..addFlag('inactive', negatable: false)
    ..addFlag('include-tests', negatable: false)
    ..addFlag('include-examples', negatable: false)
    ..addFlag('include-vendored', negatable: false)
    ..addFlag('force', negatable: false)
    ..addFlag('dry-run', negatable: false)
    ..addFlag('help', abbr: 'h', negatable: false)
    ..addFlag('version', negatable: false);

  /// Parses [arguments], defaulting to `summary` when no command is supplied.
  static CodeBusterCliOptions parse(List<String> arguments) {
    final ArgResults results = parser.parse(arguments);
    if (results.flag('help') || results.flag('version')) {
      return _from(results, CodeBusterCommand.summary, const <String>[]);
    }
    final List<String> positional = results.rest;
    final CodeBusterCommand command = positional.isEmpty
        ? CodeBusterCommand.summary
        : CodeBusterCommand.parse(positional.first);
    return _from(results, command, positional.skip(1).toList(growable: false));
  }

  /// Generates Bash, Zsh, or Fish command completion source.
  static String completions(String shell) {
    final String commands = CodeBusterCommand.values
        .map((CodeBusterCommand command) => command.name)
        .join(' ');
    return switch (shell) {
      'fish' =>
        'complete -c cb -f -a "$commands"\n'
            'complete -c cb -l root -r\n'
            'complete -c cb -l lang -r\n'
            'complete -c cb -l format -a "text json ndjson markdown sarif junit mermaid"',
      'zsh' =>
        '#compdef cb\n'
            "_arguments '1:command:($commands)' "
            "'--root[project root]:dir:_files -/' "
            "'--lang[language]:' "
            "'--format[format]:(text json ndjson markdown sarif junit mermaid)'",
      _ => 'complete -W "$commands" cb',
    };
  }

  static CodeBusterCliOptions _from(
    ArgResults results,
    CodeBusterCommand command,
    List<String> targets,
  ) {
    final String changedBase = results.flag('changed')
        ? 'HEAD'
        : results['changed-base'] as String? ?? '';
    return CodeBusterCliOptions(
      command: command,
      root: results['root'] as String,
      language:
          results['lang'] as String? ?? results['language'] as String? ?? '',
      languages: (results['languages'] as List<String>)
          .expand((String value) => value.split(','))
          .where((String value) => value.isNotEmpty)
          .toList(growable: false),
      top: int.tryParse(results['top'] as String) ?? 0,
      format: ReportFormat.parse(results['format'] as String),
      includes: results['include'] as List<String>,
      excludes: results['exclude'] as List<String>,
      only: results['only'] as String? ?? '',
      baseline: results['baseline'] as String? ?? '',
      ingestSarif: results['ingest-sarif'] as List<String>,
      output: results['output'] as String? ?? '',
      changedBase: changedBase,
      changedLines:
          results.flag('changed-lines') ||
          (command == CodeBusterCommand.pr && changedBase.isNotEmpty),
      failOnIssues: results.flag('fail-on-issues') || results.flag('ci'),
      verbose: results.flag('verbose'),
      ci: results.flag('ci'),
      allowEmpty: results.flag('allow-empty'),
      includeAll: results.flag('all'),
      includeAdvisory: results.flag('advisory'),
      allFindings: results.flag('all-findings'),
      findingGroup: results['group'] as String? ?? '',
      inactiveRules: results.flag('inactive'),
      includeTests: results.flag('include-tests'),
      includeExamples: results.flag('include-examples'),
      includeVendored: results.flag('include-vendored'),
      force: results.flag('force'),
      dryRun: results.flag('dry-run'),
      targets: targets,
    );
  }
}
