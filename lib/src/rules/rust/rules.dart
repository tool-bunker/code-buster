// Rust findings focus on explicit failure, unsafe boundaries, leaked ownership, debug residue, and shell execution that deserve review in production source.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../languages/rust/rust_adapter.dart';

/// A narrow Rust source rule with stable metadata and comment/string masking.
final class RustSourceRule extends SelfContainedRule {
  /// Creates one independently configurable Rust rule.
  RustSourceRule({
    required String id,
    required RuleSeverity severity,
    required String title,
    required String why,
    required String suggestion,
    required this.pattern,
    required this.message,
    FindingTaxonomy taxonomy = FindingTaxonomy.correctness,
    this.includeStrings = false,
    this.allowedLints = const <String>[],
    String group = 'core',
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title: title,
           why: why,
           version: 4,
           suggestion: suggestion,
           semanticMaturity: RuleSemanticMaturity.token,
           taxonomy: <FindingTaxonomy>{taxonomy},
           languages: const <String>['rust'],
           limitations: const <String>[
             'The rule uses masked source tokens and does not perform Rust type resolution.',
           ],
         ),
       );
  final bool includeStrings;
  final List<String> allowedLints;

  final RegExp pattern;
  final String message;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.rs') || _allowsRule(entry.value)) continue;
      final List<String> lines = _rustCodeLines(
        entry.value,
        preserveStrings: includeStrings,
      );
      final Set<int> excludedLines = <int>{
        ...rustCfgTestLines(lines),
        ..._rustAllowedLines(lines, allowedLints),
      };
      for (var index = 0; index < lines.length; index++) {
        if (!excludedLines.contains(index) && pattern.hasMatch(lines[index])) {
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

  bool _allowsRule(String source) {
    if (allowedLints.isEmpty) return false;
    final Iterable<RegExpMatch> attributes = RegExp(
      r'#!\s*\[\s*allow\s*\(([^)]*)\)\s*\]',
      multiLine: true,
    ).allMatches(source);
    return attributes.any(
      (RegExpMatch attribute) => allowedLints.any(
        (String lint) => RegExp(
          '(^|[,\\s])${RegExp.escape(lint)}([,\\s]|\$)',
        ).hasMatch(attribute.group(1)!),
      ),
    );
  }
}

Set<int> _rustAllowedLines(List<String> lines, List<String> allowedLints) {
  if (allowedLints.isEmpty) return const <int>{};
  return _rustAttributedLines(lines, (String line) {
    final RegExpMatch? attribute = RegExp(
      r'(?<!!)#\s*\[\s*allow\s*\(([^)]*)\)\s*\]',
    ).firstMatch(line);
    return attribute != null &&
        allowedLints.any(
          (String lint) => RegExp(
            '(^|[,\\s])${RegExp.escape(lint)}([,\\s]|\$)',
          ).hasMatch(attribute.group(1)!),
        );
  });
}

Set<int> _rustAttributedLines(
  List<String> lines,
  bool Function(String line) matchesAttribute,
) {
  final Set<int> result = <int>{};
  var pending = false;
  var excludedDepth = 0;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    if (excludedDepth > 0) {
      result.add(index);
      excludedDepth +=
          '{'.allMatches(line).length - '}'.allMatches(line).length;
      continue;
    }
    if (matchesAttribute(line)) {
      pending = true;
      result.add(index);
      continue;
    }
    if (pending && line.trimLeft().startsWith('#[')) {
      result.add(index);
      continue;
    }
    if (pending && line.trim().isNotEmpty) {
      result.add(index);
      excludedDepth = '{'.allMatches(line).length - '}'.allMatches(line).length;
      pending = false;
    }
  }
  return result;
}

/// Self-contained Rust rules in deterministic execution order.
final RuleRegistry rustRuleRegistry = RuleRegistry(<CodeBusterRule>[
  RustSourceRule(
    id: 'rust-unwrap',
    severity: RuleSeverity.info,
    title: 'Handle Rust failure explicitly',
    why:
        'unwrap terminates the process when a Result or Option is not successful.',
    suggestion:
        'Propagate the error, handle each variant, or document why failure is impossible.',
    pattern: RegExp(r'\.unwrap\s*\('),
    message: 'unwrap can panic on a recoverable value',
    taxonomy: FindingTaxonomy.reliability,
    allowedLints: const <String>['clippy::unwrap_used', 'unwrap_used'],
  ),
  RustSourceRule(
    id: 'rust-expect',
    severity: RuleSeverity.info,
    title: 'Review Rust expect calls',
    why:
        'expect terminates the process and its invariant can become stale as code evolves.',
    suggestion:
        'Propagate or handle the error unless the message documents a genuine invariant.',
    pattern: RegExp(r'\.expect\s*\('),
    message: 'expect can panic when its assumed invariant fails',
    taxonomy: FindingTaxonomy.reliability,
    allowedLints: const <String>['clippy::expect_used', 'expect_used'],
  ),
  RustSourceRule(
    id: 'rust-panic-macro',
    severity: RuleSeverity.warn,
    title: 'Avoid unexpected Rust panics',
    why:
        'A panic can abort useful work and cross an API boundary that should return an error.',
    suggestion:
        'Return a Result or constrain the panic to a documented unreachable invariant.',
    pattern: RegExp(r'\bpanic!\s*\('),
    message: 'explicit panic in production source',
    taxonomy: FindingTaxonomy.reliability,
    allowedLints: const <String>['clippy::panic', 'panic'],
  ),
  RustSourceRule(
    id: 'rust-unsafe-block',
    severity: RuleSeverity.info,
    title: 'Review Rust unsafe boundaries',
    why:
        'Unsafe code moves memory and aliasing invariants from the compiler to the implementation.',
    suggestion:
        'Keep the block minimal and document every invariant required for soundness.',
    pattern: RegExp(r'\bunsafe\s*\{'),
    message: 'unsafe block requires a documented soundness review',
    taxonomy: FindingTaxonomy.reliability,
  ),
  RustSourceRule(
    id: 'rust-mem-forget',
    severity: RuleSeverity.warn,
    title: 'Review deliberately forgotten Rust values',
    why:
        'mem::forget skips destruction and can permanently retain memory or external resources.',
    suggestion:
        'Use normal ownership, ManuallyDrop, or an explicit resource transfer contract.',
    pattern: RegExp(r'\b(?:std::)?mem::forget\s*\('),
    message: 'mem::forget deliberately skips destruction',
    taxonomy: FindingTaxonomy.reliability,
  ),
  RustSourceRule(
    id: 'rust-dbg-macro',
    severity: RuleSeverity.info,
    title: 'Remove Rust debug output',
    why:
        'dbg! writes file, line, expression, and value details to stderr in production builds.',
    suggestion:
        'Remove the debug call or replace it with deliberate structured logging.',
    pattern: RegExp(r'\bdbg!\s*\('),
    message: 'dbg! output remains in production source',
    taxonomy: FindingTaxonomy.style,
    group: 'nim-style',
  ),
  RustSourceRule(
    id: 'rust-todo-macro',
    severity: RuleSeverity.info,
    title: 'Finish Rust placeholder behavior',
    why: 'todo! compiles but panics whenever the unfinished path executes.',
    suggestion: 'Implement the path or return an explicit unsupported error.',
    pattern: RegExp(r'\btodo!\s*\('),
    message: 'todo! leaves an executable panic path',
    taxonomy: FindingTaxonomy.correctness,
  ),
  RustSourceRule(
    id: 'rust-command-shell',
    severity: RuleSeverity.warn,
    title: 'Review Rust shell execution',
    why:
        'Shell interpreters expand metacharacters and can turn data into commands.',
    suggestion:
        'Invoke the target executable directly with separately supplied arguments.',
    pattern: RegExp(
      r'''\bCommand::new\s*\(\s*["'](?:sh|bash|zsh|cmd|powershell|pwsh)["']''',
      caseSensitive: false,
    ),
    message: 'process command launches a shell interpreter',
    taxonomy: FindingTaxonomy.security,
    group: 'security',
    includeStrings: true,
  ),
]);

List<String> _rustCodeLines(String source, {required bool preserveStrings}) {
  final List<String> result = <String>[];
  var inBlockComment = false;
  for (final String line in source.split('\n')) {
    final StringBuffer masked = StringBuffer();
    String? quote;
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      final String next = index + 1 < line.length ? line[index + 1] : '';
      if (inBlockComment) {
        masked.write(' ');
        if (character == '*' && next == '/') {
          inBlockComment = false;
          masked.write(' ');
          index++;
        }
        continue;
      }
      if (quote != null) {
        masked.write(preserveStrings ? character : ' ');
        if (character == r'\' && next.isNotEmpty) {
          index++;
          masked.write(preserveStrings ? next : ' ');
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '/' && next == '/') {
        masked.write(' ' * (line.length - index));
        break;
      }
      if (character == '/' && next == '*') {
        inBlockComment = true;
        masked.write('  ');
        index++;
        continue;
      }
      if (character == '"') {
        quote = character;
        masked.write(preserveStrings ? character : ' ');
      } else {
        masked.write(character);
      }
    }
    result.add(masked.toString());
  }
  return result;
}
