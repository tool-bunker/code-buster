// The Dart plugin needs one definitive registry that combines semantic, Flutter, lifecycle, MVVM, and package checks.

import '../../core/rule.dart';
import 'aggregated_rule.dart';
import 'flutter_repeated_sizedbox_spacing.dart';
import 'package_cycle.dart';

/// Self-contained Dart rules in deterministic execution order.
final RuleRegistry dartRuleRegistry = RuleRegistry(<CodeBusterRule>[
  const DartPackageCycleRule(),
  const FlutterRepeatedSizedBoxSpacingRule(),
  for (final String id in dartAggregatedRuleIds) DartAggregatedRule(id),
]);
