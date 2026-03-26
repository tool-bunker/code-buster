// Wren’s compact syntax needs one lexical pass to find class, method, import, control-flow, and style issues without duplicate parsing.

import '../../core/models.dart';

/// Shared stateful source scan used by independently registered Wren rules.
final class WrenRuleAnalysis {
  /// Emits findings for [ruleId] in source order.
  List<Finding> findings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      var loopDepth = 0;
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index];
        final String line = _stripStrings(raw).trim();
        if (line.startsWith('for (') || line.startsWith('while (')) loopDepth++;
        if (line == '}' && loopDepth > 0) loopDepth--;

        void add(String id, RuleSeverity severity, String message) {
          if (id != ruleId) return;
          result.add(
            Finding(
              code: id,
              severity: severity,
              path: entry.key,
              line: index + 1,
              endLine: index + 1,
              message: message,
              confidence: 'medium',
              why: id == 'wren-number-parse-unchecked'
                  ? 'Num.fromString can return null for invalid input.'
                  : 'This Wren construct can weaken reliability, performance, or module boundaries.',
              suggestion: id == 'wren-number-parse-unchecked'
                  ? 'Check for null and report invalid external input before using the value.'
                  : 'Use the safer explicit Wren pattern described by the rule.',
            ),
          );
        }

        if (line.contains('System.print(')) {
          add(
            'wren-system-print',
            RuleSeverity.info,
            'System.print call left in code',
          );
        }
        if (loopDepth > 0 &&
            (line.contains('System.print(') ||
                line.contains('System.write('))) {
          add(
            'wren-print-in-loop',
            RuleSeverity.warn,
            'console output inside loop',
          );
        }
        if (line.contains('Fiber.abort(')) {
          add(
            'wren-fiber-abort',
            RuleSeverity.warn,
            'Fiber.abort terminates the current fiber',
          );
        }
        if (line.startsWith('foreign ')) {
          add(
            'wren-foreign-boundary',
            RuleSeverity.info,
            'foreign API boundary declared',
          );
        }
        if (line.contains('.call(') &&
            (line.contains('Fiber') || line.contains('fiber'))) {
          add(
            'wren-fiber-call',
            RuleSeverity.info,
            'fiber resumed directly with call',
          );
        }
        if (line.startsWith('import ') &&
            line.contains(' for ') &&
            ','.allMatches(line).length >= 8) {
          add('wren-broad-import', RuleSeverity.info, 'broad Wren import list');
        }
        if (line.startsWith('class ') && line.contains(' is ')) {
          add('wren-inheritance', RuleSeverity.info, 'class inheritance used');
        }
        if (line.contains('Num.fromString(') &&
            !raw.toLowerCase().contains('null')) {
          add(
            'wren-number-parse-unchecked',
            RuleSeverity.info,
            'Num.fromString result may be unchecked',
          );
        }
      }
    }
    return result;
  }

  static String _stripStrings(String line) =>
      line.replaceAll(RegExp(r'''"(?:\\.|[^"\\])*"'''), '');
}
