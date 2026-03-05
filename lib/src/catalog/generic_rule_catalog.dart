// Generic findings need the same metadata as executable rules even though their detection happens inside shared analysis passes.

import '../core/models.dart';

/// Metadata for generic findings that are not standalone executable rules.
final Map<String, RuleMetadata> genericRuleCatalog = <String, RuleMetadata>{
  for (final String id in const <String>['goto-statement', 'large-file'])
    id: RuleMetadata(
      id: id,
      defaultSeverity: RuleSeverity.warn,
      group: 'core',
      title: 'Review ${id.replaceAll('-', ' ')}',
      why:
          'This pattern often indicates unfinished, redundant, or error-prone code.',
      suggestion: 'Clarify the intent or replace the suspicious construct.',
    ),
};
