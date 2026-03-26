// Every Nim pack follows this contract so findings can be combined, ordered, and checked for complete rule ownership.

import '../../core/models.dart';
import 'metadata.dart';
import 'nim_finding_order.dart';

/// Named independently selectable family of Nim semantic rules.
final class NimRulePack {
  const NimRulePack({required this.name, required this.group});

  final String name;

  final String group;

  bool contains(Finding finding) =>
      nimRuleCatalog[finding.code]?.group == group;
}

/// Validated collection of Nim rule packs.
final class NimRulePackRegistry {
  NimRulePackRegistry(Iterable<NimRulePack> packs)
    : packs = List<NimRulePack>.unmodifiable(packs) {
    final Set<String> groups = <String>{};
    for (final NimRulePack pack in this.packs) {
      if (!groups.add(pack.group)) {
        throw ArgumentError.value(pack.group, 'packs', 'duplicate Nim group');
      }
    }
  }

  factory NimRulePackRegistry.standard() =>
      NimRulePackRegistry(const <NimRulePack>[
        NimRulePack(name: 'style', group: 'nim-style'),
        NimRulePack(name: 'advanced', group: 'nim-advanced'),
        NimRulePack(name: 'design', group: 'design'),
        NimRulePack(name: 'game-engine', group: 'game-engine'),
        NimRulePack(name: 'idiomatic', group: 'idiomatic'),
        NimRulePack(name: 'security', group: 'security'),
        NimRulePack(name: 'strings', group: 'strings'),
        NimRulePack(name: 'zero-cost', group: 'zerocost'),
      ]);

  final List<NimRulePack> packs;

  List<Finding> organize(Iterable<Finding> findings) {
    final List<Finding> source = findings.toList(growable: false);
    final List<Finding> result = <Finding>[];
    for (final NimRulePack pack in packs) {
      result.addAll(source.where(pack.contains));
    }
    final List<Finding> unassigned = source
        .where(
          (Finding finding) =>
              !packs.any((NimRulePack pack) => pack.contains(finding)),
        )
        .toList(growable: false);
    if (unassigned.isNotEmpty) {
      throw StateError(
        'Nim findings missing rule packs: '
        '${unassigned.map((Finding finding) => finding.code).toSet().join(', ')}',
      );
    }
    result.sort(NimFindingOrder.compare);
    return List<Finding>.unmodifiable(result);
  }
}
