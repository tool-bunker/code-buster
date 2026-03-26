// Security-sensitive Nim calls and literals deserve stricter evidence and wording than general style diagnostics.

import '../../core/models.dart';
import 'canonical_nim_evidence.dart';

/// Executes stateful taint, capture, and deterministic-output security checks.
final class NimSecurityLineRulePack {
  final Set<String> _taintedValues = <String>{};
  final Set<String> _unorderedTables = <String>{};
  final List<int> _captureIndents = <int>[];

  /// Processes one line while retaining security flow state for the file.
  List<Finding> analyzeLine({
    required String path,
    required List<String> lines,
    required int index,
    required String line,
    required int indent,
  }) {
    final List<Finding> result = <Finding>[];
    void add(
      String id,
      RuleSeverity severity,
      String message, {
      String confidence = 'medium',
    }) {
      result.add(
        Finding(
          code: id,
          severity: severity,
          path: path,
          line: index + 1,
          endLine: index + 1,
          message: message,
          confidence: confidence,
          why:
              canonicalNimEvidence[id]?.why ??
              'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
          suggestion:
              canonicalNimEvidence[id]?.suggestion ??
              'Use the safer explicit Nim pattern documented by this rule.',
        ),
      );
    }

    while (_captureIndents.isNotEmpty && indent <= _captureIndents.last) {
      _captureIndents.removeLast();
    }
    final bool captureStart = RegExp(
      r'^(?:captureStdout|captureStderr|captureOutput|redirectStdout)',
    ).hasMatch(line);
    if (captureStart) {
      if (_captureIndents.isNotEmpty) {
        add(
          'nim-nested-stdout-capture',
          RuleSeverity.info,
          'nested stdout/stderr capture detected',
          confidence: 'low',
        );
      }
      _captureIndents.add(indent);
    }
    final RegExpMatch? assignedInput = RegExp(
      r'^(?:let|var)\s+([A-Za-z_]\w*)\s*=.*(?:readLine|paramStr|getEnv)',
      caseSensitive: false,
    ).firstMatch(line);
    if (assignedInput != null) _taintedValues.add(assignedInput.group(1)!);
    final RegExpMatch? tableDeclaration = RegExp(
      r'^(?:let|var)\s+([A-Za-z_]\w*)\s*=.*initTable\[',
    ).firstMatch(line);
    if (tableDeclaration != null && !line.contains('initOrderedTable[')) {
      _unorderedTables.add(tableDeclaration.group(1)!);
    }
    if (RegExp(r'execCmd|execShellCmd|startProcess').hasMatch(line) &&
        (line.contains('&') || line.contains(r'$')) &&
        _taintedValues.any(line.contains)) {
      add(
        'nim-tainted-exec',
        RuleSeverity.warn,
        'user/input-derived value flows into process command',
        confidence: 'low',
      );
    }
    if (line.startsWith('for ') &&
        _unorderedTables.any((String table) => line.contains(' in $table:'))) {
      final bool emits = lines
          .skip(index + 1)
          .take(8)
          .any(
            (String body) =>
                body.trim().startsWith('echo ') ||
                body.contains('result.add') ||
                body.contains('rows.add'),
          );
      if (emits) {
        add(
          'nim-unordered-table-output',
          RuleSeverity.warn,
          'unordered Table iteration contributes directly to ordered output',
        );
      }
    }
    return result;
  }
}
