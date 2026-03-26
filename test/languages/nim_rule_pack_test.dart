import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/nim/metadata.dart';
import 'package:code_buster/src/rules/nim/nim_rule_pack.dart';
import 'package:test/test.dart';

void main() {
  test('Nim implementation modules stay below the monolith limit', () {
    final List<File> modules = Directory('lib/src/rules/nim')
        .listSync()
        .whereType<File>()
        .where((File file) => file.path.endsWith('.dart'))
        .where((File file) => file.uri.pathSegments.last != 'metadata.dart')
        .toList();

    for (final File module in modules) {
      final int implementationLines = module
          .readAsLinesSync()
          .where(
            (String line) =>
                line.trim().isNotEmpty && !line.trimLeft().startsWith('///'),
          )
          .length;
      expect(
        implementationLines,
        lessThanOrEqualTo(600),
        reason: '${module.path} must be split into a focused rule pack',
      );
    }
  });

  test('standard packs cover every generated Nim catalog group', () {
    final NimRulePackRegistry registry = NimRulePackRegistry.standard();

    expect(
      registry.packs.map((NimRulePack pack) => pack.group).toSet(),
      <String>{
        for (final RuleMetadata rule in nimRuleCatalog.values) rule.group,
      },
    );
  });

  test('rejects duplicate groups and unassigned findings', () {
    expect(
      () => NimRulePackRegistry(const <NimRulePack>[
        NimRulePack(name: 'first', group: 'nim-style'),
        NimRulePack(name: 'second', group: 'nim-style'),
      ]),
      throwsArgumentError,
    );
    expect(
      () => NimRulePackRegistry(const <NimRulePack>[]).organize(const <Finding>[
        Finding(
          code: 'nim-prefer-let',
          severity: RuleSeverity.info,
          path: 'main.nim',
          line: 1,
          message: 'prefer let',
        ),
      ]),
      throwsStateError,
    );
  });
}
