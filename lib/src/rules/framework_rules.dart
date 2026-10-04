// Framework overlays reuse language parsers while keeping framework-specific rules out of language ownership.

import '../core/rule.dart';
import 'dart/aggregated_rule.dart';
import 'dart/flutter_repeated_sizedbox_spacing.dart';
import 'fastapi_quality_rules.dart';
import 'flutter_quality_rules.dart';
import 'pixijs_quality_rules.dart';
import 'svelte_quality_rules.dart';
import 'ui/ui_consistency.dart';

final class FrameworkRuleRegistry {
  const FrameworkRuleRegistry({
    required this.languageRules,
    required this.repositoryRules,
  });

  final Map<String, RuleRegistry> languageRules;
  final RuleRegistry repositoryRules;
}

/// Built-in framework overlays keyed by detected framework ID.
final Map<String, FrameworkRuleRegistry> frameworkRuleRegistries =
    <String, FrameworkRuleRegistry>{
      'flutter': FrameworkRuleRegistry(
        languageRules: <String, RuleRegistry>{
          'dart': RuleRegistry(<CodeBusterRule>[
            const FlutterRepeatedSizedBoxSpacingRule(),
            for (final String id in dartAggregatedRuleIds)
              if (id.startsWith('flutter-') || id.startsWith('mvvm-'))
                DartAggregatedRule(id),
          ]),
        },
        repositoryRules: RuleRegistry(<CodeBusterRule>[
          FlutterRepeatedInlineStyleRule(),
          FlutterThemeBypassRule(),
          FlutterParallelControlComponentRule(),
          FlutterSharedComponentBypassRule(),
          for (final String id in flutterQualityRuleMetadata.keys)
            FlutterQualityRule(id),
        ]),
      ),
      'fastapi': FrameworkRuleRegistry(
        languageRules: const <String, RuleRegistry>{},
        repositoryRules: RuleRegistry(<CodeBusterRule>[
          for (final String id in fastApiQualityRuleIds) FastApiQualityRule(id),
        ]),
      ),
      'svelte': FrameworkRuleRegistry(
        languageRules: const <String, RuleRegistry>{},
        repositoryRules: RuleRegistry(<CodeBusterRule>[
          for (final String id in svelteQualityRuleIds) SvelteQualityRule(id),
        ]),
      ),
      'pixijs': FrameworkRuleRegistry(
        languageRules: const <String, RuleRegistry>{},
        repositoryRules: RuleRegistry(<CodeBusterRule>[
          for (final String id in pixiJsQualityRuleIds) PixiJsQualityRule(id),
        ]),
      ),
    };

/// Returns active framework rules that reuse [language]'s parsed representation.
Iterable<CodeBusterRule> frameworkLanguageRules(
  Set<String> frameworks,
  String language,
) sync* {
  for (final String framework in frameworks.toList()..sort()) {
    final RuleRegistry? registry =
        frameworkRuleRegistries[framework]?.languageRules[language];
    if (registry != null) yield* registry.rules;
  }
}

/// Returns active repository-wide framework rules.
Iterable<CodeBusterRule> frameworkRepositoryRules(
  Set<String> frameworks,
) sync* {
  for (final String framework in frameworks.toList()..sort()) {
    final FrameworkRuleRegistry? registry = frameworkRuleRegistries[framework];
    if (registry != null) yield* registry.repositoryRules.rules;
  }
}
