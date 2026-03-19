// This registry is the auditable list of C and C++ checks that the plugin will execute.

import '../../core/rule.dart';
import 'source_rules.dart';

/// Self-contained C and C++ rules in deterministic execution order.
final RuleRegistry cppRuleRegistry = RuleRegistry(<CodeBusterRule>[
  cppCastRule,
  cppConstCastRule,
  cppGotoRule,
  const CppMacroConstantRule(),
  cppMallocFreeRule,
  cppManualDeleteRule,
  cppMemsetZeroRule,
  cppNonConstRefParamRule,
  cppNullRule,
  cppRandRule,
  cppRawOwningNewRule,
  cppReinterpretCastRule,
  cppUnsafeCStringRule,
  cppUsingNamespaceStdRule,
  const CppVirtualNoDestructorRule(),
]);
