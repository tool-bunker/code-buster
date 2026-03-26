// Repeated Nim semantic questions—symbol roles, scopes, and call context—are answered here so packs do not disagree.

import '../../core/models.dart';
import 'nim_file_rule_scanner.dart';
import 'nim_finding_order.dart';
import 'nim_project_rule_pack.dart';

/// Coordinates focused Nim semantic scanners and restores canonical order.
final class NimSemanticDetector {
  /// Emits parser-light, high-confidence rules across the Nim rule packs.
  List<Finding> detect(Map<String, String> sources) {
    final List<Finding> result = <Finding>[
      ...NimProjectRulePack().analyze(sources),
      for (final MapEntry<String, String> entry in sources.entries)
        ...NimFileRuleScanner().analyze(entry),
    ]..sort(NimFindingOrder.compare);
    return List<Finding>.unmodifiable(result);
  }
}
