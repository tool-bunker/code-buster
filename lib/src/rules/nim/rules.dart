// The Nim registry exposes the compatibility rule family to the shared engine and verifies that no implemented ID is orphaned.

import '../../core/rule.dart';
import 'aggregated_rule.dart';

/// Self-contained Nim rules in deterministic execution order.
final RuleRegistry nimRuleRegistry = RuleRegistry(nimAggregatedRules);
