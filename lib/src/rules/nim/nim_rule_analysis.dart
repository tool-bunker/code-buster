// This is the coordinated Nim analysis pass that runs file, type, semantic, runtime, and project packs over one repository view.

import '../../core/models.dart';
import 'nim_rule_pack.dart';
import 'nim_semantic_detector.dart';

/// Coordinates canonical Nim semantic detection through focused rule packs.
final class NimRuleAnalysis {
  /// Creates analysis with the standard Nim rule packs.
  NimRuleAnalysis({NimRulePackRegistry? packs})
    : _packs = packs ?? NimRulePackRegistry.standard();

  final NimRulePackRegistry _packs;

  /// Detects and organizes Nim findings in canonical order.
  List<Finding> analyze(Map<String, String> sources) =>
      _packs.organize(NimSemanticDetector().detect(sources));
}
