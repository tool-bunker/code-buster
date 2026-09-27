// Cross-language repository risks live here; framework overlays are registered separately.

import '../core/rule.dart';
import 'generic/clean_code_rules.dart';
import 'generic/diff_quality_rules.dart';
import 'generic/generated_code_risks.dart';
import 'generic/generic_rules.dart';
import 'generic/layout_rules.dart';
import 'security/ai_prompt_injection.dart';
import 'sql/inline_string_concat.dart';
import 'testing/runtime_bootstrap.dart';
import 'ui/ui_consistency.dart';

/// Self-contained repository rules in deterministic execution order.
final RuleRegistry repositoryRuleRegistry = RuleRegistry(<CodeBusterRule>[
  TabIndentRule(),
  TrailingWhitespaceRule(),
  LongLineRule(),
  TodoCommentRule(),
  FixmeCommentRule(),
  OperationOnSameValueRule(),
  PublicMutableStateRule(),
  CommentedOutCodeRule(),
  PlaceholderIdentifierRule(),
  MixedBoundaryResponsibilityRule(),
  RepeatedPolicyLiteralRule(),
  InconsistentPeerFileNamingRule(),
  ChangedPublicApiWithoutTestRule(),
  ChangedComplexityRegressionRule(),
  BroadRefactorInFocusedChangeRule(),
  StyleDriftInDiffRule(),
  ChangedBehaviorWithoutTestRule(),
  OptionalFeatureBundleRule(),
  AbstractionCostExceedsUseRule(),
  NewUnusedDeclarationRule(),
  SingleCallerWrapperRule(),
  UnrelatedSymbolChurnRule(),
  BooleanOptionExplosionRule(),
  ExcessiveCommentDensityRule(),
  NarratingImplementationCommentRule(),
  TrivialCommentRestatementRule(),
  SingleMethodDelegatingClassRule(),
  ParallelSchemaDefinitionRule(),
  SuspiciousCommandArgumentRule(),
  LargeNumberUngroupedRule(),
  LargeInlineListRule(),
  NeedlessBoolBranchRule(),
  const CssDuplicateDeclarationSetRule(),
  const CssDesignTokenDriftRule(),
  const HtmlParallelControlPatternRule(),
  const TestRepeatedRuntimeBootstrapRule(),
  SqlInlineStringConcatRule(),
  AiPromptInjectionInstructionRule(),
  AiUntrustedPromptConstructionRule(),
  AiModelOutputExecutionRule(),
]);
