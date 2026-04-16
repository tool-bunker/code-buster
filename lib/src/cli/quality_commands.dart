// Scores, gates, debt estimates, plans, and actions interpret the same findings, so their calculations stay together.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Reports the compact Code Buster score.
final class ScoreCommand implements CliCommandHandler {
  /// Creates the score command.
  const ScoreCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.score,
  };

  @override
  int execute(CodeBusterCliOptions options) => _score(options);
}

/// Reports quality gates, ratings, and remediation debt.
final class QualityCommand implements CliCommandHandler {
  /// Creates the quality command.
  const QualityCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.quality,
  };

  @override
  int execute(CodeBusterCliOptions options) => _quality(options);
}

/// Produces remediation plans and action lists.
final class PlanningCommand implements CliCommandHandler {
  /// Creates the planning command.
  const PlanningCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.plan,
    CodeBusterCommand.actions,
  };

  @override
  int execute(CodeBusterCliOptions options) => _plan(options);
}

int _score(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(
    options,
    command: CodeBusterCommand.summary,
  );
  final Set<String> dead = run.findings
      .where((Finding finding) => finding.code == 'dead-file')
      .map((Finding finding) => finding.path)
      .toSet();
  final Set<String> duplicate = run.findings
      .where((Finding finding) => finding.code == 'duplicate-block')
      .map((Finding finding) => finding.path)
      .toSet();
  final Set<String> cycle = run.findings
      .where((Finding finding) => finding.code == 'cycle')
      .map((Finding finding) => finding.path)
      .toSet();
  stdout.writeln('Code Buster score: ${run.files.length} files');
  for (final SourceFile file in run.files) {
    var score = 100.0;
    final List<String> reasons = <String>[];
    if (dead.contains(file.relativePath)) {
      score -= 30;
      reasons.add('dead file (-30.0)');
    }
    if (cycle.contains(file.relativePath)) {
      score -= 15;
      reasons.add('part of a cycle (-15.0)');
    }
    if (duplicate.contains(file.relativePath)) {
      score -= 10;
      reasons.add('has duplicated content (-10.0)');
    }
    final String formatted = score.toStringAsFixed(1).padLeft(5);
    stdout.writeln(
      '$formatted ${file.relativePath}${reasons.isEmpty ? '' : ' ${reasons.join(', ')}'}',
    );
  }
  return 0;
}

int _quality(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(
    options,
    command: CodeBusterCommand.summary,
  );
  final List<Finding> qualityFindings = run.actionableFindings;
  final int errors = qualityFindings
      .where((Finding item) => item.severity == RuleSeverity.error)
      .length;
  final int warnings = qualityFindings
      .where((Finding item) => item.severity == RuleSeverity.warn)
      .length;
  var debt = 0;
  final Set<String> debtGroups = <String>{};
  final Map<String, int> domains = <String, int>{};
  final Map<String, int> domainDebt = <String, int>{};
  var securityHotspots = 0;
  var securityVulnerabilities = 0;
  final Map<String, int> severity = <String, int>{
    'info': qualityFindings.length - errors - warnings,
    'warn': warnings,
    'error': errors,
  };
  for (final Finding finding in qualityFindings) {
    final SecurityFindingKind securityKind =
        RuleCatalog.lookup(finding.code)?.effectiveSecurityKind ??
        SecurityFindingKind.none;
    if (securityKind == SecurityFindingKind.hotspot) securityHotspots++;
    if (securityKind == SecurityFindingKind.vulnerability) {
      securityVulnerabilities++;
    }
    final String domain = _qualityDomain(finding.code);
    domains[domain] = (domains[domain] ?? 0) + 1;
    if (debtGroups.add(_qualityDebtGroup(finding))) {
      final int minutes =
          _debtMinutes(finding) + _occurrenceDebtMinutes(finding);
      debt += minutes;
      domainDebt[domain] = (domainDebt[domain] ?? 0) + minutes;
    }
  }
  final double debtPerFile = debt / (run.files.isEmpty ? 1 : run.files.length);
  final String rating = switch (debtPerFile) {
    0 => 'A',
    <= 5 => 'B',
    <= 15 => 'C',
    <= 30 => 'D',
    _ => 'E',
  };
  final Map<String, Map<String, num>> moduleMeasures =
      <String, Map<String, num>>{};
  for (final SourceFile file in run.files) {
    final String module = _moduleForPath(file.relativePath);
    final Map<String, num> values = moduleMeasures.putIfAbsent(
      module,
      () => <String, num>{'files': 0, 'findings': 0, 'debt_minutes': 0},
    );
    values['files'] = values['files']! + 1;
  }
  for (final Finding finding in qualityFindings) {
    final String module = _moduleForPath(finding.path);
    final Map<String, num> values = moduleMeasures.putIfAbsent(
      module,
      () => <String, num>{'files': 0, 'findings': 0, 'debt_minutes': 0},
    );
    values['findings'] = values['findings']! + 1;
    values['debt_minutes'] = values['debt_minutes']! + _debtMinutes(finding);
  }
  final Map<String, Map<String, num>> orderedModules =
      <String, Map<String, num>>{
        for (final String module in (moduleMeasures.keys.toList()..sort()))
          module: moduleMeasures[module]!,
      };
  final Map<String, num> measures = <String, num>{
    'files': run.files.length,
    'findings': qualityFindings.length,
    'errors': errors,
    'warnings': warnings,
    'info': severity['info']!,
    'debt_minutes': debt,
    'debt_minutes_per_file': double.parse(debtPerFile.toStringAsFixed(2)),
    'security_findings': domains['security'] ?? 0,
    'security_hotspots': securityHotspots,
    'security_vulnerabilities': securityVulnerabilities,
    'reliability_findings': domains['reliability'] ?? 0,
    'selected_files': run.coverage['selected'] ?? run.files.length,
    'advisory.total': run.advisoryFindings.length,
    for (final MapEntry<String, int> entry in run.advisorySummary.entries)
      'advisory.${entry.key}': entry.value,
  };
  final List<Map<String, Object>> gateConditions = run.config.qualityGates
      .map((String condition) => _evaluateGate(condition, measures))
      .toList(growable: false);
  final bool gatePassed = gateConditions.every(
    (Map<String, Object> condition) => condition['passed'] == true,
  );
  final Map<String, Object> result = <String, Object>{
    'schemaVersion': reportSchemaVersion,
    'version': 1,
    'command': 'quality',
    'scope': run.config.changedLines ? 'changed-lines' : 'repository',
    'files': run.files.length,
    'findings': qualityFindings.length,
    if (run.config.changedLines) 'new_findings': qualityFindings.length,
    if (run.coverage.isNotEmpty) 'coverage': run.coverage,
    if (run.diagnostics.isNotEmpty)
      'processingDiagnostics': run.diagnostics
          .map((ProcessingDiagnostic diagnostic) => diagnostic.toJson())
          .toList(growable: false),
    if (run.manifest != null)
      'manifest': run.manifest!.toJson(
        includeFiles: options.verbose,
        includeOperational: options.verbose,
      ),
    'gate': gatePassed ? 'pass' : 'fail',
    'measureSchemaVersion': 1,
    'measures': measures,
    'modules': orderedModules,
    'gate_conditions': gateConditions,
    'rating': rating,
    'debt_minutes': debt,
    'debt_minutes_per_file': double.parse(debtPerFile.toStringAsFixed(2)),
    'domains': domains,
    'domain_debt_minutes': domainDebt,
    'severity': severity,
  };
  if (options.format == ReportFormat.json) {
    stdout.writeln(jsonEncode(result));
  } else {
    stdout.writeln(
      'Code Buster quality: ${run.files.length} files, ${qualityFindings.length} findings',
    );
    stdout.writeln('gate: ${result['gate']} scope=${result['scope']}');
    stdout.writeln('rating: $rating debt_minutes=$debt');
    stdout.writeln(
      'domains: maintainability=${domains['maintainability'] ?? 0} '
      'reliability=${domains['reliability'] ?? 0} '
      'security=${domains['security'] ?? 0}',
    );
    stdout.writeln(
      'severity: error=$errors warn=$warnings info=${severity['info']}',
    );
  }
  return (options.failOnIssues && !gatePassed) ? 2 : 0;
}

String _moduleForPath(String sourcePath) {
  final List<String> segments = sourcePath.replaceAll('\\', '/').split('/');
  if (segments.length >= 2 &&
      const <String>{
        'packages',
        'plugins',
        'modules',
        'apps',
        'services',
      }.contains(segments.first)) {
    return '${segments[0]}/${segments[1]}';
  }
  final int sourceRoot = segments.indexOf('src');
  if (sourceRoot > 0) return segments.take(sourceRoot).join('/');
  return 'root';
}

Map<String, Object> _evaluateGate(String condition, Map<String, num> measures) {
  final RegExpMatch? match = RegExp(
    r'^\s*([a-z][a-z0-9_.]*)\s*(==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)?)\s*$',
  ).firstMatch(condition);
  if (match == null || !measures.containsKey(match.group(1))) {
    return <String, Object>{
      'condition': condition,
      'passed': false,
      'error': 'unknown or invalid measure condition',
    };
  }
  final String metric = match.group(1)!;
  final String operator = match.group(2)!;
  final num expected = num.parse(match.group(3)!);
  final num actual = measures[metric]!;
  final bool passed = switch (operator) {
    '==' => actual == expected,
    '!=' => actual != expected,
    '<=' => actual <= expected,
    '>=' => actual >= expected,
    '<' => actual < expected,
    '>' => actual > expected,
    _ => false,
  };
  return <String, Object>{
    'condition': condition,
    'measure': metric,
    'operator': operator,
    'expected': expected,
    'actual': actual,
    'passed': passed,
  };
}

int _plan(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(
    options,
    command: CodeBusterCommand.summary,
  );
  if (options.command == CodeBusterCommand.plan) {
    final Map<String, List<Finding>> groups = <String, List<Finding>>{};
    for (final Finding finding in run.findings) {
      groups.putIfAbsent(finding.code, () => <Finding>[]).add(finding);
    }
    final List<String> codes = groups.keys.toList()
      ..sort((String left, String right) {
        final int priority = _priorityRank(
          left,
        ).compareTo(_priorityRank(right));
        return priority != 0
            ? priority
            : groups[right]!.length.compareTo(groups[left]!.length);
      });
    stdout.writeln('Code Buster plan');
    if (codes.isEmpty) {
      stdout.writeln('No findings to plan from.');
      return 0;
    }
    for (var index = 0; index < codes.length; index++) {
      final String code = codes[index];
      final List<Finding> group = groups[code]!;
      final RuleSeverity worst =
          group.any((Finding finding) => finding.severity == RuleSeverity.error)
          ? RuleSeverity.error
          : group.any(
              (Finding finding) => finding.severity == RuleSeverity.warn,
            )
          ? RuleSeverity.warn
          : RuleSeverity.info;
      stdout.writeln(
        '${index + 1}. ${_planTitle(code)} (${group.length} finding${group.length == 1 ? '' : 's'}, '
        'severity: ${worst.name}, confidence: ${code == 'feature-flag' ? 'medium' : 'high'})',
      );
      stdout.writeln('   why: ${_actionWhy(code)}');
      stdout.writeln('   suggestion: ${_actionSuggestion(code)}');
      for (final Finding finding in group.take(5)) {
        stdout.writeln(
          '   - ${finding.path}:${finding.line} ${finding.message}',
        );
      }
      if (group.length > 5) {
        stdout.writeln('   - ... ${group.length - 5} more');
      }
    }
    return 0;
  }
  final Iterable<Finding> actionSource = run.findings;
  final List<Map<String, Object>> actions = actionSource
      .map(
        (Finding item) => <String, Object>{
          'path': item.path,
          'line': item.line,
          'end_line': item.endLine,
          'code': item.code,
          'severity': item.severity.name,
          'risk': switch (item.severity) {
            RuleSeverity.error => 'high',
            RuleSeverity.warn => 'medium',
            RuleSeverity.info => 'low',
          },
          'problem': item.message,
          'why': _actionWhy(item.code),
          'suggested_action': _actionSuggestion(item.code),
          'related': item.relatedFiles,
        },
      )
      .toList(growable: false);
  if (options.format == ReportFormat.json ||
      options.command == CodeBusterCommand.actions) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'schemaVersion': reportSchemaVersion,
        'version': 1,
        'command': options.command.name,
        if (options.command == CodeBusterCommand.actions)
          'root': run.config.root,
        'actions': actions,
      }),
    );
  } else {
    for (final Map<String, Object> action in actions) {
      stdout.writeln(
        '${action['severity']} ${action['path']}:${action['line']} ${action['code']} — ${action['problem']}',
      );
      if ((action['suggested_action']! as String).isNotEmpty) {
        stdout.writeln('  suggestion: ${action['suggested_action']}');
      }
    }
  }
  return options.failOnIssues && actions.isNotEmpty ? 2 : 0;
}

String _planTitle(String code) => switch (code) {
  'cycle' => 'Break cycle',
  'duplicate-block' => 'Extract shared logic',
  'feature-flag' => 'Review flag',
  'repeated-condition' => 'Repeated condition',
  'structure-missing-required-dir' => 'Structure missing required dir',
  'structure-top-level-file' => 'Structure top level file',
  'tab-indent' => 'Replace tabs',
  'trailing-whitespace' => 'Trim whitespace',
  _ => RuleCatalog.lookup(code)?.title ?? 'Review ${code.replaceAll('-', ' ')}',
};

String _actionWhy(String code) => switch (code) {
  'cycle' => 'A circular dependency exists in the module graph.',
  'duplicate-block' =>
    'The same normalized code block appears in more than one location.',
  'feature-flag' => 'A feature flag-like reference was found.',
  'tab-indent' => 'A line contains a tab character.',
  'trailing-whitespace' => 'A line has trailing whitespace.',
  _ => 'A Code Buster heuristic analyzer found a potential issue.',
};

String _actionSuggestion(String code) => switch (code) {
  'cycle' =>
    'Extract shared code into a third module or invert one dependency.',
  'duplicate-block' =>
    'Extract shared logic or raise min_duplication_lines if the duplication is intentional/noisy.',
  'feature-flag' => 'Review whether the flag is still needed and documented.',
  'tab-indent' => 'Replace tabs with spaces.',
  'trailing-whitespace' => 'Trim trailing spaces before committing.',
  _ => 'Review the finding and update code or configuration as appropriate.',
};

String _qualityDomain(String code) {
  final RuleMetadata? metadata = RuleCatalog.lookup(code);
  if (metadata != null) {
    const List<FindingTaxonomy> priority = <FindingTaxonomy>[
      FindingTaxonomy.security,
      FindingTaxonomy.reliability,
      FindingTaxonomy.correctness,
      FindingTaxonomy.architecture,
      FindingTaxonomy.performance,
      FindingTaxonomy.design,
      FindingTaxonomy.maintainability,
      FindingTaxonomy.style,
    ];
    for (final FindingTaxonomy taxonomy in priority) {
      if (metadata.effectiveTaxonomy.contains(taxonomy)) return taxonomy.name;
    }
  }
  return 'maintainability';
}

String _qualityDebtGroup(Finding finding) {
  if ((finding.code == 'duplicate-block' ||
          finding.code == 'repeated-condition') &&
      finding.relatedFiles.isNotEmpty) {
    final String ownLocation = finding.code == 'duplicate-block'
        ? '${finding.path}:${finding.line}-${finding.endLine}'
        : '${finding.path}:${finding.line}';
    final List<String> locations = <String>[
      ownLocation,
      ...finding.relatedFiles,
    ]..sort();
    return '${finding.code}|${locations.join('|')}';
  }
  return finding.fingerprint;
}

int _occurrenceDebtMinutes(Finding finding) {
  final int occurrences = finding.relatedFiles.length.clamp(0, 10);
  final int perOccurrence = switch (finding.severity) {
    RuleSeverity.error => 5,
    RuleSeverity.warn => 2,
    RuleSeverity.info => 1,
  };
  return occurrences * perOccurrence;
}

int _debtMinutes(Finding finding) => switch (finding.severity) {
  RuleSeverity.error => 60,
  RuleSeverity.warn => 30,
  RuleSeverity.info => 5,
};

int _priorityRank(String code) => switch (code) {
  'cycle' => 0,
  'dead-file' => 10,
  'large-file' ||
  'long-function' ||
  'goto-statement' ||
  'complex-function' => 20,
  'duplicate-block' => 30,
  'dead-export' || 'feature-flag' || 're-export' => 40,
  _ when code.startsWith('cs-') => 100,
  _ when code.startsWith('cpp-') => 120,
  _ when code.startsWith('java-') => 140,
  _ when code.startsWith('lua-') => 150,
  _ when code.startsWith('ts-') => 160,
  _ when code.startsWith('py-') => 170,
  _ when code.startsWith('html-') || code.startsWith('css-') => 180,
  _ when code.startsWith('sql-') => 190,
  _ when code.startsWith('regex-') => 200,
  _ when code.startsWith('nim-') => 300,
  'tab-indent' || 'trailing-whitespace' || 'long-line' => 900,
  _ => 500,
};
