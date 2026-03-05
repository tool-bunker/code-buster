// Dead files, cycles, structure limits, architecture edges, and cross-language risks emerge only after the full repository graph exists.

import '../core/rule.dart';
import 'generic/generated_code_risks.dart';
import 'generic/generic_rules.dart';
import 'generic/layout_rules.dart';
import 'security/ai_prompt_injection.dart';
import 'sql/inline_string_concat.dart';

/// Self-contained repository rules in deterministic execution order.
final RuleRegistry repositoryRuleRegistry = RuleRegistry(<CodeBusterRule>[
  TabIndentRule(),
  TrailingWhitespaceRule(),
  LongLineRule(),
  TodoCommentRule(),
  FixmeCommentRule(),
  OperationOnSameValueRule(),
  ExcessiveCommentDensityRule(),
  NarratingImplementationCommentRule(),
  TrivialCommentRestatementRule(),
  SingleMethodDelegatingClassRule(),
  ParallelSchemaDefinitionRule(),
  SuspiciousCommandArgumentRule(),
  LargeNumberUngroupedRule(),
  LargeInlineListRule(),
  NeedlessBoolBranchRule(),
  SqlInlineStringConcatRule(),
  AiPromptInjectionInstructionRule(),
  AiUntrustedPromptConstructionRule(),
  AiModelOutputExecutionRule(),
]);
