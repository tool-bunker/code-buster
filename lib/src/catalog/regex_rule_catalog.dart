// Regex diagnostics are emitted by one scanner, so their user-facing metadata lives here rather than in separate rule classes.

import '../core/models.dart';

/// Rule metadata for the regex rule family.
final Map<String, RuleMetadata> regexRuleCatalog = <String, RuleMetadata>{
  for (final String id in const <String>[
    'regex-a-z-range',
    'regex-catastrophic-backtracking-risk',
    'regex-empty-alternative',
    'regex-invalid',
    'regex-leading-dot-star',
    'regex-repeated-compile',
    'regex-single-literal',
    'regex-unanchored-validation',
  ])
    id: RuleMetadata(
      id: id,
      defaultSeverity:
          const <String>{
            'regex-a-z-range',
            'regex-catastrophic-backtracking-risk',
            'regex-invalid',
            'regex-unanchored-validation',
          }.contains(id)
          ? RuleSeverity.warn
          : RuleSeverity.info,
      group: 'regex',
      title: 'Review ${id.substring(6).replaceAll('-', ' ')}',
      why:
          'This regular expression can be invalid, inefficient, misleading, or unsafe for validation.',
      suggestion:
          'Simplify, anchor, precompile, or test the expression against adversarial input.',
      version: id == 'regex-catastrophic-backtracking-risk'
          ? 3
          : id == 'regex-invalid'
          ? 2
          : 1,
      limitations: id == 'regex-invalid'
          ? <String>[
              'Dart syntax validation is limited to raw non-interpolated literals.',
            ]
          : id == 'regex-catastrophic-backtracking-risk'
          ? <String>[
              'Bounded optional outer groups are excluded from risk findings.',
              'Escaped literal parentheses are not treated as group boundaries.',
            ]
          : const <String>[],
    ),
};
