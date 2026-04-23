import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('historical rule inventory records groups and safe-fix boundaries', () {
    final Map<String, dynamic> fixture =
        jsonDecode(
              File(
                'test/fixtures/historical_rule_inventory.json',
              ).readAsStringSync(),
            )
            as Map<String, dynamic>;
    final Map<String, dynamic> groups =
        fixture['legacy_rule_groups'] as Map<String, dynamic>;
    final List<dynamic> legacyFixes =
        fixture['legacy_safe_fixes'] as List<dynamic>;
    final List<dynamic> dartFixes = fixture['dart_safe_fixes'] as List<dynamic>;

    expect(fixture['schema_version'], 1);
    expect(groups, hasLength(263));
    expect(groups['cycle'], 'core');
    expect(groups['nim-game-loop-allocation'], 'game-engine');
    expect(groups['py-eval-exec'], 'security');
    expect(
      legacyFixes,
      orderedEquals(<String>[
        'nim-std-import',
        'tab-indent',
        'trailing-whitespace',
      ]),
    );
    expect(
      dartFixes,
      orderedEquals(<String>['tab-indent', 'trailing-whitespace']),
    );

    for (final RuleMetadata rule in RuleCatalog.all) {
      if (groups.containsKey(rule.id)) {
        expect(groups[rule.id], rule.group, reason: rule.id);
      }
    }
  });
}
