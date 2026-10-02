// Every report and configuration lookup needs one authoritative view of rule IDs, defaults, taxonomy, and maturity.

import '../core/models.dart';
import '../core/rule.dart';
import '../rules/framework_rules.dart';
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
    'unused-configuration-option': RuleMetadata(
      id: 'unused-configuration-option',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Remove an unused configuration option',
      why:
          'A configuration option that every caller supplies but the implementation never reads adds misleading variation and maintenance cost.',
      suggestion:
          'Remove the option from callers and its configuration type until the implementation needs it.',
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'csharp',
        'dart',
        'javascript',
        'typescript',
        'python',
      ],
      limitations: <String>[
        'Reports identifier-named options supplied through inline object literals or named constructor arguments to private functions with at least three visible call sites.',
        'Requires a configuration-like parameter name, a project-unique function name, complete direct-call evidence, and property-only reads of the configuration parameter.',
        'String-keyed maps, positional configuration constructors, aliases, destructuring, computed property access, reflection, overload ownership, and framework-discovered private hooks are not resolved.',
      ],
    ),
    'unused-customization-hook': RuleMetadata(
      id: 'unused-customization-hook',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Remove an unused customization hook',
      why:
          'An unused callback hook adds branching and API surface for variation that has no current caller.',
      suggestion:
          'Remove the hook and its fallback path until a concrete caller needs customization.',
      version: 3,
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'csharp',
        'dart',
        'javascript',
        'typescript',
        'python',
      ],
      limitations: <String>[
        'Reports optional callback-like parameters on private C# methods and underscore-prefixed Dart, JavaScript, TypeScript, or Python functions with at least three visible call sites and a project-unique name.',
        'Requires the function body to invoke the hook and complete evidence that no visible caller supplies it.',
        'Reflective calls, method tear-offs, overload ownership, forwarded callback parameters, and framework-discovered private hooks are not resolved.',
      ],
    ),
    'unused-optional-parameter': RuleMetadata(
      id: 'unused-optional-parameter',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Remove an unused optional parameter',
      why:
          'An optional parameter that every caller omits adds API surface and a dormant behavior path without current variation.',
      suggestion:
          'Use the default behavior directly and remove the parameter until a concrete caller needs variation.',
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'csharp',
        'dart',
        'javascript',
        'typescript',
        'python',
      ],
      limitations: <String>[
        'Reports used optional parameters on private C# methods and underscore-prefixed Dart, JavaScript, TypeScript, or Python functions with at least three visible call sites and a project-unique name.',
        'Requires complete evidence that no visible caller supplies the parameter and leaves invoked callback-like parameters to unused-customization-hook.',
        'Reflective calls, method tear-offs, overload ownership, forwarded parameters, and framework-discovered private hooks are not resolved.',
      ],
    ),
    'constant-argument-parameter': RuleMetadata(
      id: 'constant-argument-parameter',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Remove a constant argument parameter',
      why:
          'A parameter whose callers always supply one value advertises flexibility that the current code does not use.',
      suggestion:
          'Move the constant into the private function and remove the parameter until callers need real variation.',
      version: 3,
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'cpp',
        'csharp',
        'dart',
        'go',
        'java',
        'javascript',
        'typescript',
        'python',
        'rust',
      ],
      limitations: <String>[
        'Visibility support is limited to static C/C++ functions, private C#/Java methods, underscore-prefixed Dart/JavaScript/TypeScript/Python functions, unexported Go functions, and non-public Rust functions.',
        'Supports required positional parameters whose values are booleans, null sentinels, numeric literals, enum values, or uppercase constants.',
        'String constants, named and optional parameters, reflective calls, method tear-offs, overload ownership, and framework-discovered private hooks are not resolved.',
      ],
    ),
    'single-product-factory': RuleMetadata(
      id: 'single-product-factory',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Inline a single-product factory',
      why:
          'A one-caller factory with one fixed product and no owned policy, lifecycle, or transformation adds indirection without current variation.',
      suggestion:
          'Construct the product at the caller until selection, lifecycle, or shared creation policy is needed.',
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'cpp',
        'csharp',
        'dart',
        'java',
        'javascript',
        'typescript',
        'python',
      ],
      limitations: <String>[
        'Reports only static C/C++ functions, private C#/Java methods, and underscore-prefixed Dart/JavaScript/TypeScript/Python factories with exactly one visible caller.',
        'Requires a factory-like name and a body consisting only of direct construction with unchanged positional arguments.',
        'Factories that select products, own lifecycle, cache, validate, decorate, transform arguments, or expose public composition boundaries are excluded.',
      ],
    ),
    'single-use-trivial-wrapper': RuleMetadata(
      id: 'single-use-trivial-wrapper',
      defaultSeverity: RuleSeverity.info,
      group: 'yagni',
      title: 'Inline a single-use trivial wrapper',
      why:
          'A single-use forwarding function adds navigation without owning policy, transformation, validation, or resource lifetime.',
      suggestion:
          'Inline the wrapper unless it is an intentional extension or compatibility boundary.',
      version: 3,
      semanticMaturity: RuleSemanticMaturity.token,
      requirements: <RuleAnalysisRequirement>{
        RuleAnalysisRequirement.functions,
      },
      taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
      languages: <String>[
        'cpp',
        'csharp',
        'dart',
        'go',
        'java',
        'javascript',
        'typescript',
        'python',
        'rust',
      ],
      limitations: <String>[
        'Visibility support is limited to static C/C++ functions, private C#/Java methods, underscore-prefixed Dart/JavaScript/TypeScript/Python functions, unexported Go functions, and non-public Rust functions.',
        'Requires unchanged positional arguments and a uniquely named local target function.',
        'Method tear-offs, reflective calls, overload ownership, and framework-discovered private hooks are not resolved.',
      ],
    ),
    'complex-function': RuleMetadata(
      id: 'complex-function',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Reduce complexity',
      why: 'A function exceeds configured complexity thresholds.',
      suggestion:
          'Split the function, simplify branching, or raise thresholds if intentional.',
      version: 7,
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
      version: 6,
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
      version: 9,
    ),
    'duplicate-block': RuleMetadata(
      id: 'duplicate-block',
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Extract shared logic',
      why: 'The same normalized code block appears in more than one location.',
      suggestion:
          'Extract shared logic or raise min_duplication_lines if the duplication is intentional.',
      version: 11,
      limitations: <String>[
        'At most 32 deterministic locations are retained per fingerprint.',
        'Predominantly literal data tables are excluded.',
        'Block-comment license headers are excluded.',
        'Python hash-comment license headers are excluded.',
        'SQL migration and archive history is excluded from duplication comparison.',
        'Mutually exclusive single-tag Go build flavors are excluded.',
        'Dart constructors composed only of field- and super-formal parameter forwarding are excluded.',
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
    for (final FrameworkRuleRegistry framework
        in frameworkRuleRegistries.values)
      for (final RuleRegistry registry in framework.languageRules.values)
        for (final RuleMetadata metadata in registry.metadata)
          metadata.id: metadata,
    for (final FrameworkRuleRegistry framework
        in frameworkRuleRegistries.values)
      for (final RuleMetadata metadata in framework.repositoryRules.metadata)
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
