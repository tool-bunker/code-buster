// A rule ID should lead to a concise explanation without requiring a full repository analysis.

import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Explains one stable rule.
final class ExplainCommand implements CliCommandHandler {
  /// Creates the explain command.
  const ExplainCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.explain,
  };

  @override
  int execute(CodeBusterCliOptions options) => _explain(options);
}

int _explain(CodeBusterCliOptions options) {
  final String? code = options.target;
  if (code == null || code.isEmpty) {
    stderr.writeln('explain requires a rule ID');
    return 64;
  }
  final RuleMetadata? rule = RuleCatalog.lookup(code);
  if (rule == null) {
    stderr.writeln('unknown or unimplemented rule: $code');
    return 1;
  }
  stdout.writeln(rule.id);
  stdout.writeln('Version: ${rule.version}');
  stdout.writeln('Semantic maturity: ${rule.semanticMaturity.name}');
  stdout.writeln('Security kind: ${rule.effectiveSecurityKind.name}');
  stdout.writeln(
    'Taxonomy: ${rule.effectiveTaxonomy.map((FindingTaxonomy taxonomy) => taxonomy.name).join(', ')}',
  );
  stdout.writeln(
    'Requirements: ${rule.requirements.map((RuleAnalysisRequirement requirement) => requirement.name).join(', ')}',
  );
  stdout.writeln(
    'Languages: ${rule.languages.isEmpty ? 'descriptor-derived' : rule.languages.join(', ')}',
  );
  if (rule.languageVersions.isNotEmpty) {
    stdout.writeln(
      'Language versions: ${rule.languageVersions.entries.map((MapEntry<String, String> entry) => '${entry.key} ${entry.value}').join(', ')}',
    );
  }
  if (rule.limitations.isNotEmpty) {
    stdout.writeln('Limitations: ${rule.limitations.join('; ')}');
  }
  stdout.writeln();
  stdout.writeln('What it means:');
  stdout.writeln('  ${rule.why}');
  stdout.writeln();
  stdout.writeln('Confidence:');
  stdout.writeln(
    rule.id == 'feature-flag'
        ? '  Medium. Some project-specific flag containers may be false positives.'
        : '  High. Heuristic finding; review surrounding code and project conventions.',
  );
  stdout.writeln();
  stdout.writeln('Suggested fixes:');
  stdout.writeln('  ${rule.suggestion}');
  return 0;
}
