// Freezes zero-configuration behavior so compatibility changes require an
// explicit review instead of silently changing existing users' analyses.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

const String _contractPath = 'test/fixtures/default_policy_contract.json';

void main(List<String> arguments) {
  final Map<String, Object?> contract = _currentContract();
  final String encoded = const JsonEncoder.withIndent('  ').convert(contract);
  final File file = File(_contractPath);
  if (arguments.contains('--update')) {
    file.writeAsStringSync('$encoded\n');
    stdout.writeln(_contractPath);
    return;
  }
  if (!file.existsSync()) {
    stderr.writeln('missing default policy contract: $_contractPath');
    exitCode = 1;
    return;
  }
  final Object? expected = jsonDecode(file.readAsStringSync());
  if (const _DeepCollectionEquality().equals(expected, contract)) return;
  stderr.writeln(
    'default policy changed; review compatibility evidence and run '
    '`dart run tool/default_contract.dart --update` only after approval',
  );
  exitCode = 1;
}

Map<String, Object?> _currentContract() {
  const AnalysisConfig defaults = AnalysisConfig(root: '.');
  final Directory temporary = Directory.systemTemp.createTempSync(
    'code-buster-default-contract-',
  );
  late final RepositoryDefaults repositoryDefaults;
  try {
    repositoryDefaults = RepositoryDefaults.infer(temporary.path);
  } finally {
    temporary.deleteSync(recursive: true);
  }
  final List<RuleMetadata> rules = RuleCatalog.all.toList()
    ..sort(
      (RuleMetadata left, RuleMetadata right) => left.id.compareTo(right.id),
    );
  return <String, Object?>{
    'schemaVersion': 1,
    'analysisDefaults': <String, Object?>{
      'languages': <String>[defaults.language],
      'ruleGroups': defaults.ruleGroups.toList()..sort(),
      'minDuplicationLines': defaults.minDuplicationLines,
      'complexityThreshold': defaults.complexityThreshold,
      'cognitiveThreshold': defaults.cognitiveThreshold,
      'maxFileLines': defaults.maxFileLines,
      'maxFunctionLines': defaults.maxFunctionLines,
    },
    'productionIgnores': repositoryDefaults.ignores,
    'rules': <Map<String, Object?>>[
      for (final RuleMetadata rule in rules)
        <String, Object?>{
          'id': rule.id,
          'severity': rule.defaultSeverity.name,
          'group': rule.group,
          'version': rule.version,
          'semanticMaturity': rule.semanticMaturity.name,
          'securityKind': rule.effectiveSecurityKind.name,
          'taxonomy':
              rule.effectiveTaxonomy
                  .map((FindingTaxonomy taxonomy) => taxonomy.name)
                  .toList()
                ..sort(),
          'requirements':
              rule.requirements
                  .map(
                    (RuleAnalysisRequirement requirement) => requirement.name,
                  )
                  .toList()
                ..sort(),
          'languages': rule.languages,
          'languageVersions': rule.languageVersions,
          'limitations': rule.limitations,
          'enabledByDefault': defaults.ruleGroups.contains(rule.group),
        },
    ],
  };
}

final class _DeepCollectionEquality {
  const _DeepCollectionEquality();

  bool equals(Object? left, Object? right) {
    if (left is List<Object?> && right is List<Object?>) {
      return left.length == right.length &&
          Iterable<int>.generate(
            left.length,
          ).every((int index) => equals(left[index], right[index]));
    }
    if (left is Map<String, Object?> && right is Map<String, Object?>) {
      return left.length == right.length &&
          left.keys.every(
            (String key) =>
                right.containsKey(key) && equals(left[key], right[key]),
          );
    }
    return left == right;
  }
}
