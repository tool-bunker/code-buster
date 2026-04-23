// Proves every catalogued Nim rule has executable registry coverage rather
// than leaving metadata-only rules that can never produce a finding.

import 'dart:convert';

import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/nim/rules.dart';

void main() {
  final Set<String> implementedIds = nimRuleRegistry.metadata
      .map((RuleMetadata rule) => rule.id)
      .toSet();
  final List<String> implemented = implementedIds.toList()..sort();
  final List<String> catalogued = RuleCatalog.all
      .map((RuleMetadata rule) => rule.id)
      .where((String id) => id.startsWith('nim-'))
      .toList(growable: false);
  final List<String> missing =
      catalogued.where((String id) => !implementedIds.contains(id)).toList()
        ..sort();
  print(
    jsonEncode(<String, Object>{
      'schema_version': 1,
      'catalogued': catalogued.length,
      'implemented': implemented.length,
      'implemented_rule_ids': implemented,
      'missing_semantic_rule_ids': missing,
      'complete': missing.isEmpty,
    }),
  );
  if (missing.isNotEmpty) {
    throw StateError('${missing.length} Nim rules remain metadata-only');
  }
}
