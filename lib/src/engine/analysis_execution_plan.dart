import '../cli/cli_contract.dart';
import '../core/models.dart';
import '../core/rule_policy.dart';

/// Selects only the analysis families whose findings can reach one command.
final class AnalysisExecutionPlan {
  AnalysisExecutionPlan({
    required this.command,
    required AnalysisConfig config,
    this.only = '',
    this.group = '',
  }) : _policy = RulePolicy(config);

  final CodeBusterCommand command;
  final String only;
  final String group;
  final RulePolicy _policy;

  bool get isComplete => const <CodeBusterCommand>{
    CodeBusterCommand.summary,
    CodeBusterCommand.review,
    CodeBusterCommand.pr,
    CodeBusterCommand.test,
  }.contains(command);

  bool allows(String ruleId) {
    if (_policy.modeFor(ruleId) == RuleMode.off) return false;
    if (only.isNotEmpty && ruleId != only) return false;
    if (group.isNotEmpty && RulePolicy.taxonomyGroupFor(ruleId) != group) {
      return false;
    }
    return switch (command) {
      CodeBusterCommand.graph => false,
      CodeBusterCommand.dead =>
        _graphRuleIds.contains(ruleId) ||
            ruleId == 'dead-export' ||
            ruleId == 're-export',
      CodeBusterCommand.duplication ||
      CodeBusterCommand.clusters => _duplicationRuleIds.contains(ruleId),
      CodeBusterCommand.structure => ruleId.startsWith('structure-'),
      CodeBusterCommand.flags => ruleId == 'feature-flag',
      CodeBusterCommand.complexity => _complexityRuleIds.contains(ruleId),
      _ => true,
    };
  }

  bool requires(Iterable<String> ruleIds) => ruleIds.any(allows);

  bool requiresMetadata(Iterable<RuleMetadata> metadata) =>
      metadata.any((RuleMetadata rule) => allows(rule.id));

  static const Set<String> graphRuleIds = _graphRuleIds;
  static const Set<String> duplicationRuleIds = _duplicationRuleIds;
  static const Set<String> complexityRuleIds = _complexityRuleIds;

  /// Whether language plugins must extract dependency edges.
  bool get requiresLanguageGraph =>
      command == CodeBusterCommand.graph ||
      only.isEmpty ||
      _graphRuleIds.contains(only);

  /// Whether language plugins must extract function bodies and signatures.
  bool get requiresFunctions =>
      only.isEmpty ||
      command == CodeBusterCommand.complexity ||
      command == CodeBusterCommand.duplication ||
      command == CodeBusterCommand.clusters ||
      _complexityRuleIds.contains(only) ||
      _functionRuleIds.contains(only);

  static const Set<String> _graphRuleIds = <String>{
    'cycle',
    'dead-file',
    'architecture-forbidden-dependency',
    'architecture-layer-cycle',
    'dart-package-cycle',
    'dart-layer-violation',
  };

  static const Set<String> _duplicationRuleIds = <String>{
    'duplicate-block',
    'near-duplicate-function',
    'parallel-contract-implementation',
    'dart-overlapping-data-model',
    'repeated-condition',
  };

  static const Set<String> _complexityRuleIds = <String>{
    'complex-function',
    'cognitive-complexity',
    'long-function',
    'goto-statement',
  };

  static const Set<String> _functionRuleIds = <String>{
    'single-use-trivial-wrapper',
    'single-product-factory',
    'constant-argument-parameter',
    'unused-customization-hook',
    'unused-optional-parameter',
    'unused-configuration-option',
    'near-duplicate-function',
    'parallel-contract-implementation',
    'repeated-condition',
  };
}
