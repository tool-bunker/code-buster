// The Dart plugin needs one definitive registry that combines semantic, Flutter, lifecycle, MVVM, and package checks.

import '../../core/rule.dart';
import 'aggregated_rule.dart';
import 'flutter_repeated_sizedbox_spacing.dart';
import 'oop_abstraction_bypass.dart';
import 'oop_collaboration_candidates.dart';
import 'oop_contract_candidates.dart';
import 'oop_design_candidates.dart';
import 'oop_inheritance_candidates.dart';
import 'oop_ownership_candidates.dart';
import 'oop_workflow_candidates.dart';
import 'package_cycle.dart';

/// Self-contained Dart rules in deterministic execution order.
final RuleRegistry dartRuleRegistry = RuleRegistry(<CodeBusterRule>[
  const DartPackageCycleRule(),
  const FlutterRepeatedSizedBoxSpacingRule(),
  for (final String id in dartOopAbstractionBypassRuleIds)
    DartOopAbstractionBypassRule(id),
  for (final String id in dartOopContractCandidateRuleIds)
    DartOopContractCandidateRule(id),
  for (final String id in dartOopDesignCandidateRuleIds)
    DartOopDesignCandidateRule(id),
  for (final String id in dartOopWorkflowCandidateRuleIds)
    DartOopWorkflowCandidateRule(id),
  for (final String id in dartOopOwnershipCandidateRuleIds)
    DartOopOwnershipCandidateRule(id),
  for (final String id in dartOopCollaborationCandidateRuleIds)
    DartOopCollaborationCandidateRule(id),
  for (final String id in dartOopInheritanceCandidateRuleIds)
    DartOopInheritanceCandidateRule(id),
  for (final String id in dartAggregatedRuleIds) DartAggregatedRule(id),
]);
