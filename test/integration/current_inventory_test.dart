import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('generated current inventory matches live Dart contracts', () {
    final Map<String, Object?> root =
        jsonDecode(
              File(
                'test/fixtures/current_contract_inventory.json',
              ).readAsStringSync(),
            )
            as Map<String, Object?>;
    final Map<String, Object?> dart = root['dart']! as Map<String, Object?>;

    expect(
      (dart['commands']! as List<Object?>).cast<String>(),
      CodeBusterCommand.values
          .map((CodeBusterCommand command) => command.name)
          .toList()
        ..sort(),
    );
    final List<String> parityRules = (dart['rules']! as List<Object?>)
        .cast<String>();
    final Set<String> implementedRules = RuleCatalog.all
        .map((RuleMetadata rule) => rule.id)
        .toSet();
    expect(implementedRules, containsAll(parityRules));
    expect(
      implementedRules.where((String id) => id.startsWith('mvvm-')),
      hasLength(5),
    );
    expect(root['generated_from'], <Object?>['lib/src']);
  });
}
