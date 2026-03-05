// Every report and configuration lookup needs one authoritative view of rule IDs, defaults, taxonomy, and maturity.

import '../core/models.dart';
import '../core/rule.dart';
import '../rules/language_rules.dart';
import '../rules/repository_rules.dart';
import 'generic_rule_catalog.dart';
import 'regex_rule_catalog.dart';

/// Stable metadata for every rule currently implemented by the Dart adapter.
final class RuleCatalog {
  RuleCatalog._();

  /// Returns metadata by stable rule ID, or `null` for an unimplemented rule.
  static RuleMetadata? lookup(String id) => _byId[id];

  /// Returns metadata by stable rule ID and fails on incomplete rule wiring.
  static RuleMetadata require(String id) {
    final RuleMetadata? metadata = lookup(id);
    if (metadata != null) return metadata;
    throw StateError('Executable rule `$id` has no RuleCatalog metadata.');
  }

  /// Rejects executable rules missing from the derived built-in catalog.
  static void validateExecutableRules(Iterable<CodeBusterRule> rules) {
    for (final CodeBusterRule rule in rules) {
      final RuleMetadata metadata = rule.metadata;
      final RuleMetadata catalogMetadata = require(metadata.id);
      if (!identical(metadata, catalogMetadata)) {
        throw StateError(
          'Executable rule `${metadata.id}` is not its registered metadata.',
        );
      }
    }
  }

  /// All implemented rules in deterministic identifier order.
  static List<RuleMetadata> get all => List<RuleMetadata>.unmodifiable(
    _byId.values.toList()..sort(
      (RuleMetadata left, RuleMetadata right) => left.id.compareTo(right.id),
    ),
  );

  /// Stable behavior signature for every implemented rule.
  static String get versionSignature => versionSignatureFor(all);

  /// Builds deterministic cache material for a selected set of rules.
  static String versionSignatureFor(Iterable<RuleMetadata> rules) {
    final List<RuleMetadata> ordered = rules.toList()
      ..sort(
        (RuleMetadata left, RuleMetadata right) => left.id.compareTo(right.id),
      );
    return ordered
        .map((RuleMetadata metadata) => '${metadata.id}@${metadata.version}')
        .join(',');
  }

  static final Map<String, RuleMetadata> _byId = <String, RuleMetadata>{
    for (final String id in const <String>[
      'architecture-forbidden-dependency',
      'architecture-layer-cycle',
    ])
      id: RuleMetadata(
        id: id,
        defaultSeverity: RuleSeverity.error,
        group: 'core',
        title: 'Enforce architecture dependency direction',
        why:
            'Architecture boundaries keep dependency direction and ownership explicit.',
        suggestion:
            'Move, invert, or extract the dependency to satisfy declared policy.',
        semanticMaturity: RuleSemanticMaturity.project,
        requirements: const <RuleAnalysisRequirement>{
          RuleAnalysisRequirement.graph,
        },
        taxonomy: const <FindingTaxonomy>{FindingTaxonomy.architecture},
      ),
    'mvvm-forbidden-dependency': const RuleMetadata(
      id: 'mvvm-forbidden-dependency',
      defaultSeverity: RuleSeverity.error,
      group: 'architecture',
      title: 'Enforce MVVM dependency direction',
      why:
          'MVVM layers remain testable when presentation, state, domain, and data dependencies point in deliberate directions.',
      suggestion:
          'Move the dependency behind a ViewModel or invert it through a model/repository abstraction.',
      semanticMaturity: RuleSemanticMaturity.project,
      requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.graph},
      languages: <String>['dart'],
    ),
    for (final String id in const <String>[
      'constant-argument-parameter',
      'single-use-trivial-wrapper',
      'unused-customization-hook',
    ])
      id: RuleMetadata(
        id: id,
        defaultSeverity: RuleSeverity.info,
        group: 'yagni',
        title: 'Review ${id.replaceAll('-', ' ')}',
        why:
            'This abstraction may advertise flexibility that current callers do not use.',
        suggestion:
            'Simplify the API until multiple concrete uses justify the abstraction.',
      ),
    'complex-function': RuleMetadata(
      id: 'complex-function',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Reduce complexity',
      why: 'A function exceeds configured complexity thresholds.',
      suggestion:
          'Split the function, simplify branching, or raise thresholds if intentional.',
      version: 6,
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
        RuleAnalysisRequirement.tokens,
      },
      limitations: <String>[
        'JavaScript and TypeScript extraction covers named declarations, methods, and block-bodied variable arrow functions.',
        'Anonymous callbacks and expression-bodied arrow functions are not measured.',
      ],
    ),
    'cycle': RuleMetadata(
      id: 'cycle',
      defaultSeverity: RuleSeverity.error,
      group: 'core',
      title: 'Break cycle',
      why: 'A circular dependency exists in the module graph.',
      suggestion:
          'Extract shared code into a third module or invert one dependency.',
      version: 2,
      semanticMaturity: RuleSemanticMaturity.project,
      requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.graph},
    ),
    'dead-export': const RuleMetadata(
      id: 'dead-export',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Remove or privatize unused export',
      why:
          'Unused public declarations expand API surface and maintenance burden.',
      suggestion:
          'Remove it, make it private, or document external/framework use.',
    ),
    're-export': const RuleMetadata(
      id: 're-export',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Review facade re-export',
      why: 'Re-export facades can hide ownership and increase coupling.',
      suggestion:
          'Keep the facade intentional and documented, or import the owner directly.',
    ),
    'dead-file': RuleMetadata(
      id: 'dead-file',
      defaultSeverity: RuleSeverity.error,
      group: 'core',
      title: 'Remove or connect file',
      why: 'A source file is not reachable from configured entry points.',
      suggestion:
          'Remove the file, add an entry point, or add the missing dependency edge.',
    ),
    'duplicate-block': RuleMetadata(
      id: 'duplicate-block',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Extract shared logic',
      why: 'The same normalized code block appears in more than one location.',
      suggestion:
          'Extract shared logic or raise min_duplication_lines if the duplication is intentional.',
      version: 7,
      limitations: <String>[
        'At most 32 deterministic locations are retained per fingerprint.',
        'Predominantly literal data tables are excluded.',
        'Block-comment license headers are excluded.',
        'Python hash-comment license headers are excluded.',
        'SQL migration history is excluded from duplication comparison.',
      ],
    ),
    'feature-flag': RuleMetadata(
      id: 'feature-flag',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Review feature flag',
      why: 'A feature flag-like reference was found.',
      suggestion: 'Review whether the flag is still needed and documented.',
      version: 2,
      limitations: <String>[
        'Generic Flags, flags, and Config members require feature lifecycle terminology.',
      ],
    ),
    'long-function': RuleMetadata(
      id: 'long-function',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Split long function',
      why: 'A function exceeds the configured source line threshold.',
      suggestion:
          'Extract focused helpers or raise the threshold if intentional.',
    ),
    'near-duplicate-function': RuleMetadata(
      id: 'near-duplicate-function',
      defaultSeverity: RuleSeverity.info,
      group: 'core',
      title: 'Consolidate similar functions',
      why: 'Two function bodies are structurally similar.',
      suggestion:
          'Extract shared behavior if their distinction is not intentional.',
    ),
    'parallel-contract-implementation': const RuleMetadata(
      id: 'parallel-contract-implementation',
      defaultSeverity: RuleSeverity.info,
      group: 'maintainability',
      title: 'Consolidate external contract handling',
      why:
          'Separate implementations of one external contract can drift independently.',
      suggestion:
          'Choose one owner for the contract and share or delegate decoding and policy.',
      semanticMaturity: RuleSemanticMaturity.project,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      limitations: <String>[
        'Semantic mode currently compares HTTP endpoints, JSON key sets, SQL table operations, and configuration key sets.',
        'A shared external contract can be intentional; findings require review.',
      ],
    ),
    'repeated-condition': RuleMetadata(
      id: 'repeated-condition',
      defaultSeverity: RuleSeverity.info,
      group: 'design',
      title: 'Consolidate condition',
      why: 'A complex condition is repeated across multiple locations.',
      suggestion:
          'Extract a named predicate or document the intentional repetition.',
    ),
    'structure-missing-required-dir': RuleMetadata(
      id: 'structure-missing-required-dir',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Create required directory',
      why: 'A configured source subdirectory is missing.',
      suggestion: 'Create the directory or update the structure configuration.',
    ),
    'structure-missing-source-root': RuleMetadata(
      id: 'structure-missing-source-root',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Create source root',
      why: 'A configured source root is missing.',
      suggestion:
          'Create the root or remove it from the structure configuration.',
    ),
    'structure-top-level-file': RuleMetadata(
      id: 'structure-top-level-file',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Reduce top-level files',
      why: 'A source root has more top-level files than configured.',
      suggestion:
          'Move implementation into subsystem folders or allow intentional facade files.',
    ),
    ...genericRuleCatalog,
    ...regexRuleCatalog,
    for (final RuleRegistry registry in languageRuleRegistries.values)
      for (final RuleMetadata metadata in registry.metadata)
        metadata.id: metadata,
    for (final RuleMetadata metadata in repositoryRuleRegistry.metadata)
      metadata.id: metadata,
    'unused-generic-parameter': const RuleMetadata(
      id: 'unused-generic-parameter',
      defaultSeverity: RuleSeverity.warn,
      group: 'yagni',
      title: 'Remove unused generic',
      why: 'A generic parameter does not affect the API or implementation.',
      suggestion:
          'Remove it unless phantom typing is an intentional documented requirement.',
    ),
  };
}
