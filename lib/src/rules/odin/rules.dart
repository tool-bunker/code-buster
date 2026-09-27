// Odin rules focus on explicit failure and low-level memory boundaries that deserve review.

import '../../core/models.dart';
import '../../core/rule.dart';

/// One narrow Odin source rule with comment and literal masking.
final class OdinSourceRule extends SelfContainedRule {
  OdinSourceRule({
    required String id,
    required RuleSeverity severity,
    required String title,
    required String why,
    required String suggestion,
    required this.pattern,
    required this.message,
    FindingTaxonomy taxonomy = FindingTaxonomy.correctness,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: 'core',
           title: title,
           why: why,
           suggestion: suggestion,
           semanticMaturity: RuleSemanticMaturity.token,
           taxonomy: <FindingTaxonomy>{taxonomy},
           languages: const <String>['odin'],
           limitations: const <String>[
             'The rule masks nested comments and literals but does not perform Odin type resolution.',
           ],
         ),
       );

  final RegExp pattern;
  final String message;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.odin')) continue;
      final List<String> lines = _odinCodeLines(source.value);
      for (var index = 0; index < lines.length; index++) {
        if (!pattern.hasMatch(lines[index])) continue;
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: message,
          confidence: 'high',
        );
      }
    }
  }
}

/// Self-contained Odin rules in deterministic execution order.
final RuleRegistry odinRuleRegistry = RuleRegistry(<CodeBusterRule>[
  OdinSourceRule(
    id: 'odin-panic-call',
    severity: RuleSeverity.warn,
    title: 'Avoid unexpected Odin panics',
    why: 'panic terminates normal control flow instead of returning an error.',
    suggestion:
        'Return an error value unless this is a documented unrecoverable invariant.',
    pattern: RegExp(r'\bpanic\s*\('),
    message: 'panic call can terminate the process',
    taxonomy: FindingTaxonomy.reliability,
  ),
  OdinSourceRule(
    id: 'odin-transmute',
    severity: RuleSeverity.info,
    title: 'Review Odin transmute boundaries',
    why:
        'transmute reinterprets bits under caller-owned size and representation invariants.',
    suggestion:
        'Prefer a checked conversion or document the representation invariant.',
    pattern: RegExp(r'\btransmute\s*\('),
    message: 'transmute requires a representation invariant',
    taxonomy: FindingTaxonomy.reliability,
  ),
  OdinSourceRule(
    id: 'odin-raw-pointer',
    severity: RuleSeverity.info,
    title: 'Review Odin raw pointer boundaries',
    why:
        'rawptr removes pointee type information and shifts memory validity checks to the implementation.',
    suggestion:
        'Keep raw pointer use narrow and document lifetime, alignment, and ownership invariants.',
    pattern: RegExp(r'\brawptr\b'),
    message: 'raw pointer use requires a memory-safety review',
    taxonomy: FindingTaxonomy.reliability,
  ),
  OdinSourceRule(
    id: 'odin-undefined-value',
    severity: RuleSeverity.warn,
    title: 'Initialize Odin values before use',
    why:
        'The undefined value marker bypasses normal zero initialization and can expose indeterminate data.',
    suggestion:
        'Initialize the value explicitly unless immediate complete initialization is proven.',
    pattern: RegExp(r'(?:=|:)\s*---(?:\s|$|[,}])'),
    message: 'undefined value marker bypasses initialization',
    taxonomy: FindingTaxonomy.correctness,
  ),
]);

List<String> _odinCodeLines(String source) {
  final List<String> result = <String>[];
  var blockDepth = 0;
  for (final String line in source.split('\n')) {
    final StringBuffer code = StringBuffer();
    String? quote;
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      final String next = index + 1 < line.length ? line[index + 1] : '';
      if (blockDepth > 0) {
        code.write(' ');
        if (character == '/' && next == '*') {
          blockDepth++;
          code.write(' ');
          index++;
        } else if (character == '*' && next == '/') {
          blockDepth--;
          code.write(' ');
          index++;
        }
        continue;
      }
      if (quote != null) {
        code.write(' ');
        if (quote != '`' && character == r'\' && next.isNotEmpty) {
          code.write(' ');
          index++;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '/' && next == '/') {
        code.write(' ' * (line.length - index));
        break;
      }
      if (character == '/' && next == '*') {
        blockDepth = 1;
        code.write('  ');
        index++;
      } else if (character == '"' || character == "'" || character == '`') {
        quote = character;
        code.write(' ');
      } else {
        code.write(character);
      }
    }
    result.add(code.toString());
  }
  return result;
}
