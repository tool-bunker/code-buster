// All Nim line packs need identical traversal, masking, and finding assembly; this scanner supplies that shared control flow.

import '../../core/models.dart';
import 'canonical_nim_evidence.dart';
import 'nim_advanced_line_rule_pack.dart';
import 'nim_aggregate_rule_pack.dart';
import 'nim_runtime_rule_pack.dart';
import 'nim_simple_line_rule_pack.dart';
import 'nim_type_rule_pack.dart';

/// Scans one Nim source file and coordinates line-oriented rule state.
final class NimFileRuleScanner {
  /// Executes file-local semantic checks.
  List<Finding> analyze(MapEntry<String, String> entry) {
    final List<Finding> result = <Finding>[];
    final List<String> lines = entry.value.split('\n');
    final Map<String, int> mutableDeclarations = <String, int>{};
    var importCount = 0;
    var exportCount = 0;
    final bool isTest =
        entry.key.startsWith('tests/') ||
        entry.key.split('/').last.startsWith('test_');
    final String fileLower = entry.value.toLowerCase();
    final NimRuntimeRulePack runtimeRules = NimRuntimeRulePack(entry.value);
    final NimAdvancedLineRulePack advancedRules = NimAdvancedLineRulePack();
    final bool mentionsWebSocket =
        fileLower.contains('websocket') ||
        fileLower.contains('sec-websocket') ||
        (fileLower.contains('connection') && fileLower.contains('upgrade'));
    result.addAll(NimTypeRulePack().analyzeFile(entry.key, lines));
    for (var index = 0; index < lines.length; index++) {
      final String raw = lines[index];
      final String line = _withoutComment(raw).trim();
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
            path: entry.key,
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

      final RegExpMatch? variable = RegExp(
        r'^var\s+([A-Za-z_]\w*)',
      ).firstMatch(line);
      if (variable != null) mutableDeclarations[variable.group(1)!] = index;
      final String lower = line.toLowerCase();
      if (line.startsWith('import ') || line.startsWith('from ')) {
        importCount++;
        if (line.startsWith('import ') &&
            line.contains('[') &&
            line.contains(']')) {
          final String modules = line.substring(
            line.indexOf('[') + 1,
            line.lastIndexOf(']'),
          );
          final int count = modules.split(',').length;
          if (count > 8) {
            add(
              'nim-broad-import',
              RuleSeverity.info,
              'large grouped import with $count modules',
            );
          }
        }
      }
      if (line.contains('*') &&
          RegExp(
            r'^(?:proc|func|method|template|iterator|type|[A-Za-z_]\w*\*\s*(?::|=))',
          ).hasMatch(line)) {
        exportCount++;
      }
      final bool exportedType =
          line.contains('*') &&
          RegExp(
            r'=\s*(?:ref\s+)?object|=\s*tuple|=\s*enum|=\s*distinct',
          ).hasMatch(line);
      if (exportedType &&
          !(index > 0 && lines[index - 1].trim().startsWith('##'))) {
        add(
          'nim-exported-object-without-doc',
          RuleSeverity.info,
          'exported type lacks a doc comment',
          confidence: 'low',
        );
      }
      if (exportedType && line.contains('= tuple')) {
        add(
          'nim-tuple-used-as-domain-type',
          RuleSeverity.info,
          'exported tuple type may be better modeled as an object',
          confidence: 'low',
        );
      }
      if (line.contains('ref object of ')) {
        add(
          'nim-ref-object-inheritance',
          RuleSeverity.info,
          'ref object inheritance used; consider whether composition is simpler',
        );
      }
      if (line.contains('{.raises') &&
          (line.contains('CatchableError') || line.contains('Exception'))) {
        add(
          'nim-raises-catchableerror',
          RuleSeverity.info,
          'raises contract is too broad',
        );
      }
      if (line.startsWith('template ')) {
        final int templateIndent = raw.length - raw.trimLeft().length;
        final int bodyLength = lines
            .skip(index + 1)
            .takeWhile(
              (String next) =>
                  next.trim().isEmpty ||
                  next.length - next.trimLeft().length > templateIndent,
            )
            .length;
        if (bodyLength + 1 > 20) {
          add(
            'nim-large-template',
            RuleSeverity.warn,
            'template spans ${bodyLength + 1} lines',
          );
        }
      }
      final int declarationParen = line.indexOf('(');
      final bool exportedProc =
          (line.startsWith('proc ') || line.startsWith('func ')) &&
          line
              .substring(
                0,
                declarationParen < 0 ? line.length : declarationParen,
              )
              .contains('*');
      if (exportedProc) {
        if (line.contains('cstring')) {
          add(
            'nim-cstring-public-api',
            RuleSeverity.info,
            'exported API exposes cstring',
          );
        }
        if (RegExp(r'(?:\bptr\s+|:\s*ptr\b|\bpointer\b)').hasMatch(line)) {
          add(
            'nim-pointer-public-api',
            RuleSeverity.info,
            'exported API exposes a raw pointer',
          );
        }
        if (RegExp(
          r'\)\s*:\s*var\s+(?:int|bool|float|string|char)\b',
        ).hasMatch(line)) {
          add(
            'nim-public-var-scalar-accessor',
            RuleSeverity.warn,
            'exported API returns mutable scalar access',
          );
        }
        final RegExpMatch? constructor = RegExp(
          r'^(?:proc|func)\s+(?:init|new)([A-Z][A-Za-z0-9_]*)\*?\s*\(',
        ).firstMatch(line);
        if (constructor != null &&
            !RegExp(
              ':\\s*(?:ref\\s+)?${RegExp.escape(constructor.group(1)!)}\\b',
            ).hasMatch(line)) {
          add(
            'nim-constructor-name',
            RuleSeverity.info,
            'constructor-style name does not return the matching type',
            confidence: 'low',
          );
        }
      }
      final int indent = raw.length - raw.trimLeft().length;
      result.addAll(
        runtimeRules.analyzeLine(
          path: entry.key,
          source: entry.value,
          lines: lines,
          index: index,
          raw: raw,
          line: line,
          lower: lower,
        ),
      );
      result.addAll(
        advancedRules.analyzeLine(
          path: entry.key,
          source: entry.value,
          lines: lines,
          index: index,
          raw: raw,
          line: line,
          lower: lower,
          indent: indent,
          isTest: isTest,
          mentionsWebSocket: mentionsWebSocket,
        ),
      );
      result.addAll(
        NimSimpleLineRulePack().analyze(
          path: entry.key,
          source: entry.value,
          lines: lines,
          index: index,
          raw: raw,
          line: line,
          isTest: isTest,
        ),
      );
    }
    result.addAll(
      NimAggregateRulePack().analyze(
        path: entry.key,
        source: entry.value,
        lines: lines,
        isTest: isTest,
        fileLower: fileLower,
        mentionsWebSocket: mentionsWebSocket,
        cameraModified: runtimeRules.cameraModified,
        cameraRestored: runtimeRules.cameraRestored,
        cameraProcLine: runtimeRules.cameraProcLine,
        assetLoadCount: runtimeRules.assetLoadCount,
        assetFreeCount: runtimeRules.assetFreeCount,
        renderBeginCount: runtimeRules.renderBeginCount,
        renderEndCount: runtimeRules.renderEndCount,
        renderProcLine: runtimeRules.renderProcLine,
        procParameters: runtimeRules.procParameters,
        genericHookCount: advancedRules.genericHookCount,
        hasImport: advancedRules.hasImport,
        hasGenericSerializationWrapper:
            advancedRules.hasGenericSerializationWrapper,
        jsonApiCount: advancedRules.jsonApiCount,
        importCount: importCount,
        exportCount: exportCount,
        distinctTypes: advancedRules.distinctTypes,
        dumpTypes: advancedRules.dumpTypes,
        parseTypes: advancedRules.parseTypes,
        mutableDeclarations: mutableDeclarations,
      ),
    );
    return result;
  }

  String _withoutComment(String line) {
    var quote = '';
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      if ((character == '"' || character == "'") &&
          (index == 0 || line[index - 1] != r'\')) {
        quote = quote.isEmpty ? character : (quote == character ? '' : quote);
      } else if (character == '#' && quote.isEmpty) {
        return line.substring(0, index);
      }
    }
    return line;
  }
}
