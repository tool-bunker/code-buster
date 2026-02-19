// Rule metadata drives grouping and security treatment; these policy functions keep those decisions out of reporters and commands.

import '../catalog/rule_catalog.dart';
import 'models.dart';

/// Resolves effective rule visibility without coupling analyzers to reporting.
final class RulePolicy {
  /// Creates a resolver for one effective analysis configuration.
  const RulePolicy(this.config);

  /// Configuration supplying group and per-rule overrides.
  final AnalysisConfig config;

  /// Returns the effective mode for [ruleId].
  RuleMode modeFor(String ruleId) {
    if (config.disabledRules.contains(ruleId)) return RuleMode.off;
    final RuleMode? explicitRule = config.ruleModes[ruleId];
    if (explicitRule != null) return explicitRule;
    if (config.severityOverrides.containsKey(ruleId)) return RuleMode.report;
    final RuleMode? explicitGroup = config.groupModes[taxonomyGroupFor(ruleId)];
    if (explicitGroup != null) return explicitGroup;
    if (const <String>{
      'flutter-gesture-semantic-gap',
      'flutter-listener-without-remove',
    }.contains(ruleId)) {
      return RuleMode.count;
    }
    final String taxonomy = taxonomyGroupFor(ruleId);
    if (ruleId.startsWith('dart-') &&
        const <String>{'correctness', 'reliability'}.contains(taxonomy) &&
        !_defaultActionableDartRules.contains(ruleId)) {
      return RuleMode.count;
    }
    return config.groupModes[taxonomy] ?? defaultModeForGroup(taxonomy);
  }

  /// Returns the stable cross-language semantic group for [ruleId].
  static String taxonomyGroupFor(String ruleId) {
    final RuleMetadata? metadata = RuleCatalog.lookup(ruleId);
    final String legacyGroup = metadata?.group ?? 'correctness';
    final Set<FindingTaxonomy> taxonomy =
        metadata?.taxonomy ?? const <FindingTaxonomy>{};
    if (taxonomy.contains(FindingTaxonomy.architecture)) {
      return 'architecture';
    }
    if (taxonomy.contains(FindingTaxonomy.security)) return 'security';
    if (taxonomy.contains(FindingTaxonomy.reliability)) return 'reliability';
    if (taxonomy.contains(FindingTaxonomy.performance)) return 'performance';
    if (taxonomy.contains(FindingTaxonomy.style)) return 'style';
    if (taxonomy.contains(FindingTaxonomy.correctness)) return 'correctness';
    if (taxonomy.contains(FindingTaxonomy.design)) return 'maintainability';
    if (ruleId.startsWith('architecture-') ||
        ruleId == 'dart-package-cycle' ||
        ruleId == 'dart-layer-violation' ||
        ruleId == 'dart-feature-public-api-leak' ||
        ruleId == 'dart-public-dynamic-api' ||
        ruleId == 'dart-service-locator-in-domain' ||
        ruleId == 'dart-barrel-export-cycle') {
      return 'architecture';
    }
    if (legacyGroup == 'game-engine') return 'domain';
    if (metadata?.effectiveSecurityKind != SecurityFindingKind.none ||
        legacyGroup == 'security' ||
        ruleId.contains('hardcoded-secret') ||
        ruleId.contains('path-traversal') ||
        ruleId.contains('sql-interpolation') ||
        ruleId.contains('untrusted') ||
        ruleId.contains('unsafe-deserialization') ||
        ruleId.contains('sensitive-data') ||
        ruleId.contains('bad-certificate')) {
      return 'security';
    }
    if (_accessibilityRules.contains(ruleId)) return 'accessibility';
    if (_reliabilityRules.contains(ruleId)) return 'reliability';
    if (_performanceRules.contains(ruleId)) return 'performance';
    if (_styleRules.contains(ruleId)) return 'style';
    if (_maintainabilityRules.contains(ruleId)) return 'maintainability';
    if (legacyGroup == 'reliability') return 'reliability';
    if (_correctnessRules.contains(ruleId)) return 'correctness';
    if (legacyGroup == 'core' &&
        !const <String>{
          'complex-function',
          'duplicate-block',
          'feature-flag',
          'large-file',
        }.contains(ruleId)) {
      return 'correctness';
    }
    if (legacyGroup == 'nim-style' ||
        legacyGroup == 'idiomatic' ||
        legacyGroup == 'strings' ||
        legacyGroup == 'zerocost') {
      return 'style';
    }
    if (legacyGroup == 'suspicious' ||
        legacyGroup == 'regex' ||
        legacyGroup == 'sql') {
      return 'suspicious';
    }
    return 'maintainability';
  }

  /// Stable default policy for built-in semantic groups.
  static RuleMode defaultModeForGroup(String group) => switch (group) {
    'core' ||
    'correctness' ||
    'security' ||
    'reliability' ||
    'accessibility' => RuleMode.report,
    'performance' ||
    'maintainability' ||
    'style' ||
    'nim-style' ||
    'suspicious' ||
    'design' ||
    'yagni' ||
    'regex' ||
    'sql' ||
    'idiomatic' ||
    'nim-advanced' ||
    'strings' ||
    'zerocost' => RuleMode.count,
    'architecture' ||
    'game-engine' ||
    'domain' ||
    'experimental' => RuleMode.off,
    _ => RuleMode.count,
  };

  /// Default modes used by configuration loading and `cb init`.
  static const Map<String, RuleMode> defaultGroupModes = <String, RuleMode>{
    'correctness': RuleMode.report,
    'core': RuleMode.report,
    'security': RuleMode.report,
    'reliability': RuleMode.report,
    'accessibility': RuleMode.report,
    'performance': RuleMode.count,
    'maintainability': RuleMode.count,
    'style': RuleMode.count,
    'nim-style': RuleMode.count,
    'suspicious': RuleMode.count,
    'design': RuleMode.count,
    'yagni': RuleMode.count,
    'regex': RuleMode.count,
    'sql': RuleMode.count,
    'idiomatic': RuleMode.count,
    'nim-advanced': RuleMode.count,
    'strings': RuleMode.count,
    'zerocost': RuleMode.count,
    'architecture': RuleMode.off,
    'game-engine': RuleMode.off,
  };
}

const Set<String> _correctnessRules = <String>{
  'cycle',
  'dead-export',
  'dead-file',
  'dart-unreachable-statement',
  'dart-catch-return-null',
  'dart-throw-string',
  'dart-dynamic',
  'dart-null-assertion',
  'dart-copy-with-missing-field',
  'dart-enum-name-persistence',
  'dart-late-final-persistence',
  'dart-json-cast-without-validation',
  'dart-json-serialization-asymmetry',
  'flutter-set-state-after-await',
  'flutter-stream-created-in-build',
  'flutter-global-key-created-in-build',
  'flutter-listener-without-remove',
  'flutter-provider-watch-in-callback',
  'flutter-expanded-outside-flex',
  'flutter-image-network-no-error-builder',
};

const Set<String> _reliabilityRules = <String>{
  'dart-blocking-in-async',
  'dart-broad-catch',
  'dart-catch-without-stack-trace',
  'dart-controller-not-disposed',
  'dart-future-in-for-each',
  'dart-http-client-not-closed',
  'dart-iosink-not-closed',
  'dart-isolate-not-terminated',
  'dart-receive-port-not-closed',
  'dart-random-access-file-not-closed',
  'dart-stream-subscription-not-cancelled',
  'dart-synchronous-file-io-in-async',
  'dart-timer-not-cancelled',
  'dart-unawaited-future',
};

const Set<String> _accessibilityRules = <String>{
  'flutter-unbounded-scrollable',
  'flutter-gesture-semantic-gap',
};

const Set<String> _performanceRules = <String>{
  'dart-regexp-created-in-loop',
  'dart-string-concat-in-loop',
  'dart-repeated-iterable-traversal',
  'dart-quadratic-list-membership',
};

const Set<String> _styleRules = <String>{
  'tab-indent',
  'trailing-whitespace',
  'long-line',
  'dart-print',
  'dart-late-mutable',
  'dart-dynamic',
  'dart-null-assertion',
};
const Set<String> _maintainabilityRules = <String>{
  'complex-function',
  'duplicate-block',
  'feature-flag',
  'large-file',
  'dart-recommended-lints-missing',
  'dart-overlapping-data-model',
};

const Set<String> _defaultActionableDartRules = <String>{
  'dart-unreachable-statement',
};
