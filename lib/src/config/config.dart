// Loading TOML and applying defaults is centralized here so every entry point sees the same effective configuration.

import 'dart:io';

import 'package:toml/toml.dart';

import '../core/models.dart';
import '../core/rule_policy.dart';
import 'config_validator.dart';

export 'config_migrator.dart';
export 'config_validator.dart';

/// Loads `code-buster.toml` into the language-neutral analysis configuration.
final class CodeBusterConfigLoader {
  /// Reads `code-buster.toml` under [root], returning defaults when it is absent.
  static AnalysisConfig loadFromRoot(String root) {
    final File file = File('$root${Platform.pathSeparator}code-buster.toml');
    if (!file.existsSync()) {
      return AnalysisConfig(root: root);
    }
    return loadFromString(root: root, source: file.readAsStringSync());
  }

  /// Parses a `code-buster.toml` source string using Code Buster-compatible defaults.
  static AnalysisConfig loadFromString({
    required String root,
    required String source,
  }) {
    final Map<String, dynamic> values = TomlDocument.parse(
      _normalizeLegacyPipeEscapes(source),
    ).toMap();
    final Map<String, dynamic> analysis = _table(values, 'analysis');
    final Map<String, dynamic> files = _table(values, 'files');
    final Map<String, dynamic> rules = _table(values, 'rules');
    final Map<String, dynamic> classification = _table(
      values,
      'classification',
    );
    final Map<String, dynamic> review = _table(values, 'review');
    final Map<String, dynamic> quality = _table(values, 'quality');
    final String qualityProfile = _string(
      quality,
      'profile',
      fallback: 'standard',
    );
    final Map<String, dynamic> architecture = _table(values, 'architecture');
    final Map<String, dynamic> mvvm = _table(architecture, 'mvvm');
    final Map<String, dynamic> structure = _table(values, 'structure');
    final Map<String, dynamic> severity = _table(values, 'severity');
    final Map<String, dynamic> ruleSeverity = _table(rules, 'severity');
    final _SeveritySettings severitySettings = _severitySettings(
      ruleSeverity.isEmpty ? severity : ruleSeverity,
    );
    final List<String> configuredGroups = _preferredStringList(
      rules,
      'enabled_groups',
      values,
      'rule_groups',
    );
    final Map<String, RuleMode> groupModes = <String, RuleMode>{
      ..._ruleModes(_table(rules, 'groups'), scope: 'group'),
    };
    for (final String group in configuredGroups) {
      for (final String semanticGroup in _semanticGroupsForLegacy(group)) {
        groupModes[semanticGroup] = RuleMode.report;
      }
    }
    if (_string(architecture, 'profile', fallback: '').isNotEmpty ||
        _stringList(architecture, 'layers').isNotEmpty ||
        _stringList(architecture, 'allowed_dependencies').isNotEmpty ||
        _stringList(architecture, 'denied_dependencies').isNotEmpty) {
      groupModes['architecture'] = RuleMode.report;
    }
    final Map<String, RuleMode> ruleModes = _ruleModes(
      _table(rules, 'mode'),
      scope: 'rule',
    );
    final Set<String> disabledRules = <String>{
      ...severitySettings.disabledRules,
      for (final MapEntry<String, RuleMode> entry in ruleModes.entries)
        if (entry.value == RuleMode.off) entry.key,
    };
    final Set<String> activeGroups = <String>{
      for (final MapEntry<String, RuleMode> entry
          in RulePolicy.defaultGroupModes.entries)
        if (entry.value != RuleMode.off) entry.key,
      for (final MapEntry<String, RuleMode> entry in groupModes.entries)
        if (entry.value != RuleMode.off) entry.key,
      ...configuredGroups,
    };
    activeGroups.removeWhere(
      (String group) => groupModes[group] == RuleMode.off,
    );
    return AnalysisConfig(
      root: root,
      language: _string(values, 'lang', fallback: 'auto'),
      languages: _stringList(values, 'languages'),
      includes: _stringList(files, 'include'),
      excludes: _stringList(files, 'exclude'),
      changedBase: _string(review, 'changed_base', fallback: ''),
      entryPoints: _preferredStringList(
        files,
        'entry_points',
        values,
        'entry_points',
      ),
      ignorePatterns: _preferredStringList(
        files,
        'ignore',
        values,
        'ignore_patterns',
      ),
      classificationProduction: _stringList(classification, 'production'),
      classificationTest: _stringList(classification, 'test'),
      classificationGenerated: _stringList(classification, 'generated'),
      minDuplicationLines: _preferredInteger(
        analysis,
        'duplication_min_lines',
        values,
        'min_duplication_lines',
        fallback: qualityProfile == 'strict' ? 10 : 15,
      ),
      duplicationMode: _duplicationMode(
        _string(analysis, 'duplication_mode', fallback: 'exact'),
      ),
      complexityThreshold: _preferredInteger(
        analysis,
        'complexity_threshold',
        values,
        'complexity_threshold',
        fallback: qualityProfile == 'strict' ? 8 : 10,
      ),
      cognitiveThreshold: _preferredInteger(
        analysis,
        'cognitive_complexity_threshold',
        values,
        'cognitive_threshold',
        fallback: qualityProfile == 'strict' ? 12 : 15,
      ),
      maxFileLines: _preferredInteger(
        analysis,
        'max_file_lines',
        values,
        'max_file_lines',
        fallback: 0,
      ),
      maxFunctionLines: _preferredInteger(
        analysis,
        'max_function_lines',
        values,
        'max_function_lines',
        fallback: 0,
      ),
      qualityProfile: qualityProfile,
      qualityGates: _stringList(quality, 'gates').isNotEmpty
          ? _stringList(quality, 'gates')
          : switch (qualityProfile) {
              'strict' => const <String>[
                'findings == 0',
                'debt_minutes_per_file <= 5',
              ],
              'security' => const <String>['security_vulnerabilities == 0'],
              _ => const <String>['findings == 0'],
            },
      csharpDeadCode: _preferredBoolean(
        analysis,
        'csharp_dead_code',
        values,
        'csharp_dead_code',
        fallback: false,
      ),
      ruleGroups: activeGroups,
      disabledRules: disabledRules,
      severityOverrides: severitySettings.overrides,
      groupModes: Map<String, RuleMode>.unmodifiable(groupModes),
      ruleModes: Map<String, RuleMode>.unmodifiable(ruleModes),
      patternRules:
          _preferredStringList(rules, 'patterns', values, 'pattern_rules')
              .map(PatternRuleParser.parse)
              .where(
                (PatternRule rule) =>
                    rule.id.isNotEmpty && rule.pattern.isNotEmpty,
              )
              .toList(growable: false),
      structureSourceRoots: _stringList(structure, 'source_roots').isEmpty
          ? _stringList(values, 'structure_source_roots')
          : _stringList(structure, 'source_roots'),
      structureMaxTopLevelFiles: _preferredInteger(
        structure,
        'max_root_files',
        structure,
        'max_top_level_files',
        fallback: _integer(
          values,
          'structure_max_top_level_files',
          fallback: -1,
        ),
      ),
      structureAllowedTopLevel:
          _preferredStringList(
            structure,
            'allowed_root_files',
            structure,
            'allowed_top_level',
          ).isEmpty
          ? _stringList(values, 'structure_allowed_top_level')
          : _preferredStringList(
              structure,
              'allowed_root_files',
              structure,
              'allowed_top_level',
            ),
      architectureLayers: _stringList(architecture, 'layers'),
      architectureAllowedDependencies: _stringList(
        architecture,
        'allowed_dependencies',
      ),
      architectureDeniedDependencies: _stringList(
        architecture,
        'denied_dependencies',
      ),
      architectureProfile: _string(architecture, 'profile', fallback: ''),
      mvvmViews: _stringList(mvvm, 'views'),
      mvvmViewModels: _stringList(mvvm, 'view_models'),
      mvvmModels: _stringList(mvvm, 'models'),
      mvvmRepositories: _stringList(mvvm, 'repositories'),
      mvvmStrictViewModelBoundary: _boolean(
        mvvm,
        'strict_view_model_boundary',
        fallback: true,
      ),
      structureRequiredDirectories:
          _preferredStringList(
            structure,
            'required_directories',
            structure,
            'required_dirs',
          ).isEmpty
          ? _stringList(values, 'structure_required_dirs')
          : _preferredStringList(
              structure,
              'required_directories',
              structure,
              'required_dirs',
            ),
    );
  }

  /// Returns actionable schema diagnostics without running analysis.
  static List<String> validate(String source) {
    final Map<String, dynamic> values;
    try {
      values = TomlDocument.parse(_normalizeLegacyPipeEscapes(source)).toMap();
    } on Object catch (error) {
      return <String>['invalid TOML: $error'];
    }
    return CodeBusterConfigValidator.validate(
      values,
      verifyLoad: () => loadFromString(root: '.', source: source),
    );
  }

  /// Returns the initial configuration created by `code-buster init`.
  static String starterConfig() => '''# Optional repository-specific overrides.
# Code Buster already detects languages, frameworks, generated files, and
# production source conventions when this file is absent.
languages = ["auto"]
''';
}

/// Parses Code Buster's pipe-delimited project pattern-rule syntax.
final class PatternRuleParser {
  /// Parses one `id|severity|pattern|message|...` rule definition.
  static PatternRule parse(String value) {
    final List<String> fields = _splitFields(value);
    if (fields.length < 4) {
      return const PatternRule(
        id: '',
        severity: RuleSeverity.warn,
        pattern: '',
        message: '',
      );
    }
    return PatternRule(
      id: fields[0].trim(),
      severity: RuleSeverity.parse(fields[1].trim()),
      pattern: fields[2],
      message: fields[3].trim(),
      suggestion: fields.length > 4 ? fields[4].trim() : '',
      patternNot: fields.length > 5 ? fields[5].trim() : '',
      fix: fields.length > 6 ? fields[6].trim() : '',
      category: fields.length > 7 ? fields[7].trim() : '',
    );
  }

  static List<String> _splitFields(String value) {
    final List<String> fields = <String>[];
    final StringBuffer field = StringBuffer();
    var escaped = false;
    for (final int codeUnit in value.codeUnits) {
      final String character = String.fromCharCode(codeUnit);
      if (escaped) {
        field.write(character == '|' ? character : '\\$character');
        escaped = false;
      } else if (character == '\\') {
        escaped = true;
      } else if (character == '|') {
        fields.add(field.toString());
        field.clear();
      } else {
        field.write(character);
      }
    }
    if (escaped) {
      field.write('\\');
    }
    fields.add(field.toString());
    return fields;
  }
}

final class _SeveritySettings {
  const _SeveritySettings(this.disabledRules, this.overrides);

  final Set<String> disabledRules;
  final Map<String, RuleSeverity> overrides;
}

_SeveritySettings _severitySettings(Map<String, dynamic> values) {
  final Set<String> disabledRules = <String>{};
  final Map<String, RuleSeverity> overrides = <String, RuleSeverity>{};
  values.forEach((String rule, dynamic rawSeverity) {
    if (rawSeverity is! String) {
      throw FormatException('Invalid code-buster.toml severity for $rule');
    }
    if (rawSeverity.toLowerCase() == 'off') {
      disabledRules.add(rule);
    } else {
      overrides[rule] = RuleSeverity.parse(rawSeverity);
    }
  });
  return _SeveritySettings(disabledRules, overrides);
}

Map<String, RuleMode> _ruleModes(
  Map<String, dynamic> values, {
  required String scope,
}) {
  final Map<String, RuleMode> modes = <String, RuleMode>{};
  values.forEach((String name, dynamic rawMode) {
    if (scope == 'group' && !_semanticRuleGroups.contains(name)) {
      throw FormatException('Unknown Code Buster semantic rule group: $name');
    }
    if (rawMode is! String) {
      throw FormatException('Invalid code-buster.toml $scope mode for $name');
    }
    modes[name] = RuleMode.parse(rawMode);
  });
  return modes;
}

const Set<String> _semanticRuleGroups = <String>{
  'correctness',
  'security',
  'reliability',
  'accessibility',
  'performance',
  'maintainability',
  'style',
  'suspicious',
  'architecture',
  'domain',
  'experimental',
};

DuplicationMode _duplicationMode(String value) => switch (value) {
  'semantic' => DuplicationMode.semantic,
  'normalized' => DuplicationMode.normalized,
  _ => DuplicationMode.exact,
};

Set<String> _semanticGroupsForLegacy(String group) => switch (group) {
  'core' => const <String>{'correctness', 'maintainability'},
  'style' ||
  'dart-style' ||
  'nim-style' ||
  'idiomatic' ||
  'strings' ||
  'zerocost' => const <String>{'style'},
  'security' => const <String>{'security'},
  'reliability' => const <String>{'reliability'},
  'game-engine' => const <String>{'domain'},
  'regex' || 'sql' || 'suspicious' => const <String>{'suspicious'},
  'design' || 'yagni' || 'nim-advanced' => const <String>{'maintainability'},
  _ when _semanticRuleGroups.contains(group) => <String>{group},
  _ => const <String>{},
};

Map<String, dynamic> _table(Map<String, dynamic> values, String key) {
  final dynamic value = values[key];
  if (value == null) {
    return const <String, dynamic>{};
  }
  if (value is Map<String, dynamic>) {
    return value;
  }
  throw FormatException('Invalid code-buster.toml table: $key');
}

String _normalizeLegacyPipeEscapes(String source) {
  final StringBuffer normalized = StringBuffer();
  var index = 0;
  while (index < source.length) {
    if (source[index] != '\\') {
      normalized.write(source[index]);
      index++;
      continue;
    }
    final int start = index;
    while (index < source.length && source[index] == '\\') {
      index++;
    }
    final int slashCount = index - start;
    if (index < source.length && source[index] == '|' && slashCount.isOdd) {
      normalized.write(List<String>.filled(slashCount + 1, '\\').join());
    } else {
      normalized.write(List<String>.filled(slashCount, '\\').join());
    }
  }
  return normalized.toString();
}

String _string(
  Map<String, dynamic> values,
  String key, {
  required String fallback,
}) {
  final dynamic value = values[key];
  if (value == null) {
    return fallback;
  }
  if (value is String) {
    return value;
  }
  throw FormatException('Invalid code-buster.toml string: $key');
}

List<String> _preferredStringList(
  Map<String, dynamic> preferred,
  String preferredKey,
  Map<String, dynamic> legacy,
  String legacyKey,
) => preferred.containsKey(preferredKey)
    ? _stringList(preferred, preferredKey)
    : _stringList(legacy, legacyKey);

int _preferredInteger(
  Map<String, dynamic> preferred,
  String preferredKey,
  Map<String, dynamic> legacy,
  String legacyKey, {
  required int fallback,
}) => preferred.containsKey(preferredKey)
    ? _integer(preferred, preferredKey, fallback: fallback)
    : _integer(legacy, legacyKey, fallback: fallback);

bool _preferredBoolean(
  Map<String, dynamic> preferred,
  String preferredKey,
  Map<String, dynamic> legacy,
  String legacyKey, {
  required bool fallback,
}) => preferred.containsKey(preferredKey)
    ? _boolean(preferred, preferredKey, fallback: fallback)
    : _boolean(legacy, legacyKey, fallback: fallback);

int _integer(Map<String, dynamic> values, String key, {required int fallback}) {
  final dynamic value = values[key];
  if (value == null) {
    return fallback;
  }
  if (value is int) {
    return value;
  }
  throw FormatException('Invalid code-buster.toml integer: $key');
}

bool _boolean(
  Map<String, dynamic> values,
  String key, {
  required bool fallback,
}) {
  final dynamic value = values[key];
  if (value == null) {
    return fallback;
  }
  if (value is bool) {
    return value;
  }
  throw FormatException('Invalid code-buster.toml boolean: $key');
}

List<String> _stringList(Map<String, dynamic> values, String key) {
  final dynamic value = values[key];
  if (value == null) {
    return const <String>[];
  }
  if (value is! List || value.any((dynamic item) => item is! String)) {
    throw FormatException('Invalid code-buster.toml string list: $key');
  }
  return List<String>.unmodifiable(value.cast<String>());
}
