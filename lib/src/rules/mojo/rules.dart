// Mojo evolves quickly, so these rules identify removed syntax and correctness risks that commonly survive copied examples.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/mojo/mojo_adapter.dart';

/// A narrow Mojo source rule with stable metadata and comment/string masking.
final class MojoSourceRule extends SelfContainedRule {
  /// Creates one independently configurable Mojo rule.
  MojoSourceRule({
    required String id,
    required RuleSeverity severity,
    required String title,
    required String why,
    required String suggestion,
    required this.pattern,
    required this.message,
    FindingTaxonomy taxonomy = FindingTaxonomy.style,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: 'nim-style',
           title: title,
           why: why,
           suggestion: suggestion,
           semanticMaturity: RuleSemanticMaturity.token,
           taxonomy: <FindingTaxonomy>{taxonomy},
           languages: const <String>['mojo'],
           limitations: const <String>[
             'The rule follows current Mojo syntax but does not perform compiler type resolution.',
           ],
         ),
       );

  final RegExp pattern;
  final String message;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.mojo')) continue;
      final List<String> lines = _mojoCodeLines(entry.value);
      for (var index = 0; index < lines.length; index++) {
        if (pattern.hasMatch(lines[index])) {
          yield report(
            context,
            path: entry.key,
            line: index + 1,
            message: message,
            confidence: 'high',
          );
        }
      }
    }
  }
}

/// Reports functions that raise without declaring a raises effect.
final class MojoMissingRaisesRule extends SelfContainedRule {
  /// Creates the Mojo raises-contract rule.
  const MojoMissingRaisesRule()
    : super(
        const RuleMetadata(
          id: 'mojo-missing-raises',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Declare Mojo raises effects',
          why:
              'Mojo functions must declare raises when an error can leave the function.',
          suggestion:
              'Add raises to the signature or handle the error inside the function.',
          semanticMaturity: RuleSemanticMaturity.token,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.correctness},
          languages: <String>['mojo'],
          limitations: <String>[
            'The rule checks explicit raise statements and does not resolve transitive throwing calls.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final FunctionSource function in MojoAdapter().functions(
      context.sources,
    )) {
      final String declaration = function.source.split('\n').first;
      if (!RegExp(r'\braise\b').hasMatch(_mojoCode(function.source)) ||
          RegExp(r'\braises\b').hasMatch(declaration)) {
        continue;
      }
      yield report(
        context,
        path: function.path,
        line: function.line,
        message: '`${function.name}` raises without a raises declaration',
        confidence: 'high',
      );
    }
  }
}

/// Self-contained Mojo rules in deterministic execution order.
final RuleRegistry mojoRuleRegistry = RuleRegistry(<CodeBusterRule>[
  MojoSourceRule(
    id: 'mojo-deprecated-fn',
    severity: RuleSeverity.warn,
    title: 'Use def for Mojo functions',
    why: 'The fn keyword is deprecated and removed from current Mojo syntax.',
    suggestion:
        'Replace fn with def and declare raises explicitly when needed.',
    pattern: RegExp(r'^\s*fn\s+[A-Za-z_]\w*'),
    message: 'deprecated fn declaration; current Mojo uses def',
  ),
  MojoSourceRule(
    id: 'mojo-deprecated-let',
    severity: RuleSeverity.warn,
    title: 'Use var for Mojo bindings',
    why: 'The let keyword was removed from current Mojo syntax.',
    suggestion: 'Replace let with var.',
    pattern: RegExp(r'^\s*let\s+[A-Za-z_]\w*'),
    message: 'deprecated let binding; current Mojo uses var',
  ),
  MojoSourceRule(
    id: 'mojo-deprecated-alias',
    severity: RuleSeverity.warn,
    title: 'Use comptime for Mojo aliases',
    why:
        'Alias declarations were replaced by comptime values and type aliases.',
    suggestion: 'Replace alias with a comptime declaration.',
    pattern: RegExp(r'^\s*alias\s+[A-Za-z_]\w*\s*='),
    message: 'deprecated alias declaration; use comptime',
  ),
  MojoSourceRule(
    id: 'mojo-parameter-decorator',
    severity: RuleSeverity.warn,
    title: 'Use Mojo comptime control flow',
    why:
        'The @parameter decorator was replaced by comptime if and comptime for.',
    suggestion: 'Replace @parameter control flow with comptime syntax.',
    pattern: RegExp(r'@parameter\b'),
    message: 'deprecated @parameter decorator; use comptime',
  ),
  MojoSourceRule(
    id: 'mojo-legacy-argument-convention',
    severity: RuleSeverity.warn,
    title: 'Use current Mojo argument conventions',
    why:
        'borrowed, inout, and owned were replaced by read, mut, and var conventions.',
    suggestion:
        'Use read/default borrowing, mut references, or var ownership as appropriate.',
    pattern: RegExp(r'\b(?:borrowed|inout|owned)\b'),
    message: 'legacy Mojo argument convention',
  ),
  MojoSourceRule(
    id: 'mojo-legacy-stdlib-import',
    severity: RuleSeverity.warn,
    title: 'Use std-prefixed Mojo imports',
    why: 'Current Mojo standard-library imports use the std package prefix.',
    suggestion:
        'Import the module from std, for example from std.pathlib import Path.',
    pattern: RegExp(
      r'^\s*from\s+(?:collections|memory|sys|os|pathlib)\s+import\b',
    ),
    message: 'standard-library import is missing the std prefix',
  ),
  MojoSourceRule(
    id: 'mojo-string-index',
    severity: RuleSeverity.info,
    title: 'Use explicit Mojo string indexing',
    why: 'Current Mojo strings require byte= indexing or codepoint iteration.',
    suggestion:
        'Use value[byte=index] for bytes or codepoint_slices() for Unicode text.',
    pattern: RegExp(
      r'\b(?:str|string|text|name|message)\w*\s*\[\s*\d+\s*\]',
      caseSensitive: false,
    ),
    message: 'string-like value uses removed positional indexing',
    taxonomy: FindingTaxonomy.correctness,
  ),
  const MojoMissingRaisesRule(),
]);

List<String> _mojoCodeLines(String source) => _mojoCode(source).split('\n');

String _mojoCode(String source) {
  final StringBuffer result = StringBuffer();
  String? quote;
  var triple = false;
  var inComment = false;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    final bool tripleDelimiter =
        index + 2 < source.length &&
        source[index + 1] == character &&
        source[index + 2] == character;
    if (inComment) {
      if (character == '\n') {
        inComment = false;
        result.write('\n');
      } else {
        result.write(' ');
      }
      continue;
    }
    if (quote != null) {
      if (character == '\n') {
        result.write('\n');
        if (!triple) quote = null;
      } else if (triple && character == quote && tripleDelimiter) {
        result.write('   ');
        index += 2;
        quote = null;
        triple = false;
      } else {
        result.write(' ');
        if (!triple && character == r'\' && next.isNotEmpty) {
          result.write(' ');
          index++;
        } else if (!triple && character == quote) {
          quote = null;
        }
      }
      continue;
    }
    if (character == '#') {
      inComment = true;
      result.write(' ');
    } else if ((character == '"' || character == "'") && tripleDelimiter) {
      quote = character;
      triple = true;
      result.write('   ');
      index += 2;
    } else if (character == '"' || character == "'") {
      quote = character;
      result.write(' ');
    } else {
      result.write(character);
    }
  }
  return result.toString();
}
