// Most commands that produce findings share the same analysis and reporting path; keeping it here prevents their behavior from drifting.

import 'dart:io';

import '../core/models.dart';
import '../core/rule_policy.dart';
import '../engine/analysis_runner.dart';
import '../reporting/reporting.dart';
import 'cli_command.dart';
import 'cli_contract.dart';

/// Handles finding-producing repository analysis commands.
final class AnalysisCommand implements CliCommandHandler {
  /// Creates the shared analysis command.
  const AnalysisCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
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
  };

  @override
  int execute(CodeBusterCliOptions options) {
    final AnalysisRun run = AnalysisRunner().run(options);
    if (run.files.isEmpty && !options.allowEmpty) {
      stderr.writeln('no source files found (use --allow-empty to allow this)');
      return 1;
    }
    final bool dedicatedDetailCommand = const <CodeBusterCommand>{
      CodeBusterCommand.dead,
      CodeBusterCommand.duplication,
      CodeBusterCommand.structure,
      CodeBusterCommand.clusters,
      CodeBusterCommand.complexity,
      CodeBusterCommand.flags,
    }.contains(options.command);
    final List<Finding> detailedFindings = options.allFindings
        ? run.activeFindings
        : options.findingGroup.isNotEmpty
        ? run.activeFindings
              .where(
                (Finding finding) =>
                    RulePolicy.taxonomyGroupFor(finding.code) ==
                    options.findingGroup,
              )
              .toList(growable: false)
        : options.includeAdvisory
        ? <Finding>[...run.actionableFindings, ...run.advisoryFindings]
        : dedicatedDetailCommand
        ? run.activeFindings
        : run.actionableFindings;
    if (options.command == CodeBusterCommand.test) {
      stdout.writeln('cb smoke test passed: ${run.files.length} files');
    } else {
      final bool color =
          options.format == ReportFormat.text && stdout.supportsAnsiEscapes;
      stdout.writeln(
        FindingReporter().render(
          format: options.format,
          command: options.command.name,
          root: run.config.root,
          files: run.files.length,
          findings: detailedFindings,
          languageSummary: run.languageSummaryFor(detailedFindings),
          actionableFindingCount: run.actionableFindings.length,
          coverage: run.coverage,
          advisorySummary: run.advisorySummary,
          manifest: run.manifest,
          diagnostics: run.diagnostics,
          verbose: options.verbose,
          color: color,
        ),
      );
    }
    return options.failOnIssues && run.actionableFindings.isNotEmpty ? 2 : 0;
  }
}
