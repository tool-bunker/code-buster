// Straightforward Nim style and safety patterns can be detected deterministically per line without paying for deeper analysis.

import '../../core/models.dart';
import 'canonical_nim_evidence.dart';

/// Executes stateless style, security, string, and idiomatic line rules.
final class NimSimpleLineRulePack {
  /// Analyzes one normalized source line.
  List<Finding> analyze({
    required String path,
    required String source,
    required List<String> lines,
    required int index,
    required String raw,
    required String line,
    required bool isTest,
  }) {
    final context = _NimSimpleLineContext(
      path: path,
      lines: lines,
      index: index,
      raw: raw,
      line: line,
    );
    _analyzeFormatting(context);
    _analyzeInput(context);
    _analyzeIdioms(context);
    _analyzeExceptions(context);
    _analyzeDeclarations(context);
    _analyzeLoops(context);
    _analyzeTypes(context);
    _analyzeCallables(context);
    _analyzeContracts(context);
    _analyzeSecurity(context);
    return context.result;
  }

  static void _analyzeFormatting(_NimSimpleLineContext context) {
    final String path = context.path;
    final String raw = context.raw;
    final String line = context.line;
    final String lower = context.lower;
    if (lower.contains('formatfloat') &&
        lower.contains('replace') &&
        line.contains("'.', ','")) {
      context.add(
        'nim-forced-decimal-comma-output',
        RuleSeverity.info,
        'formatted number is forced to use a decimal comma',
        confidence: 'high',
      );
    }
    if (line.contains('replace') &&
        line.contains(r'\t') &&
        RegExp(
          r'source|content|text|raw|file',
          caseSensitive: false,
        ).hasMatch(line)) {
      context.add(
        'nim-global-tab-replace',
        RuleSeverity.warn,
        'tabs are replaced across an entire source/text value',
      );
    }
    if (lower.contains('.strip') &&
        (lower.contains('chars=') || lower.contains('chars ='))) {
      context.add(
        'nim-strip-chars-string-set',
        RuleSeverity.info,
        'strip(chars="...") treats the string as a set of characters',
      );
    }
    if (lower.contains('skip') &&
        (path.toLowerCase().contains('test') || lower.contains('test')) &&
        !raw.contains('#')) {
      context.add(
        'nim-skip-test-without-comment',
        RuleSeverity.info,
        'test appears to be skipped without an explanatory comment',
        confidence: 'low',
      );
    }
    if (_writesUnescapedMarkup(line)) {
      context.add(
        'nim-xml-output-unescaped',
        RuleSeverity.warn,
        'dynamic value is written into XML without visible escaping',
      );
    }
    if ((line.startsWith('proc ') || line.startsWith('func ')) &&
        (line.contains('ptr ') || line.contains(': pointer')) &&
        RegExp(r'\b(?:len|size|count)?\w*\s*:\s*int').hasMatch(line)) {
      context.add(
        'nim-pointer-with-separate-size',
        RuleSeverity.info,
        'proc takes a pointer and a separate size parameter',
        confidence: 'low',
      );
    }
  }

  static bool _writesUnescapedMarkup(String line) {
    final String lower = line.toLowerCase();
    final bool writesOutput =
        lower.startsWith('echo ') ||
        lower.startsWith('echo(') ||
        RegExp(r'(?:^|\.)write(?:line)?\s*\(').hasMatch(lower);
    if (!writesOutput ||
        RegExp(
          r'\b(?:[a-z_]\w*\.)?(?:(?:xml|html)escape(?:attr)?|escape(?:html|xml|attr)?)\s*\(',
        ).hasMatch(lower)) {
      return false;
    }

    final RegExpMatch? opening = RegExp(
      r'''["']<([A-Za-z][A-Za-z0-9:._-]*)(?:\s[^>]*)?>["']''',
    ).firstMatch(line);
    if (opening == null) return false;

    final String tag = opening.group(1)!;
    final String remainder = line.substring(opening.end);
    final RegExpMatch? closing = RegExp(
      '''["']</${RegExp.escape(tag)}\\s*>["']''',
      caseSensitive: false,
    ).firstMatch(remainder);
    if (closing == null) return false;

    final String dynamicContent = _withoutQuotedText(
      remainder.substring(0, closing.start),
    );
    return RegExp(r'\b[A-Za-z_]\w*\b').hasMatch(dynamicContent);
  }

  static String _withoutQuotedText(String source) {
    final StringBuffer result = StringBuffer();
    var quote = '';
    var escaped = false;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      if (quote.isNotEmpty) {
        if (escaped) {
          escaped = false;
        } else if (character == '\\') {
          escaped = true;
        } else if (character == quote) {
          quote = '';
        }
      } else if (character == '"' || character == "'") {
        quote = character;
      } else {
        result.write(character);
      }
    }
    return result.toString();
  }

  static void _analyzeInput(_NimSimpleLineContext context) {
    final String lower = context.lower;
    if ((lower.contains('parseint(readline') ||
            lower.contains('parsefloat(readline') ||
            lower.contains('parsebool(readline')) &&
        !lower.contains('strip')) {
      context.add(
        'nim-readline-without-strip',
        RuleSeverity.info,
        'readLine result is parsed without trimming',
      );
    }
    if (lower.contains('not not ')) {
      context.add(
        'nim-double-negation',
        RuleSeverity.info,
        'double boolean negation reduces readability',
        confidence: 'low',
      );
    }
    if (lower.contains('gethomedir()') && lower.contains('strip')) {
      context.add(
        'nim-home-dir-strip',
        RuleSeverity.info,
        'home directory path is normalized with strip',
        confidence: 'low',
      );
    }
    if (lower.contains('.strip') &&
        (lower.contains('leading=false') || lower.contains('trailing=false'))) {
      context.add(
        'nim-strip-one-sided-wrapper',
        RuleSeverity.info,
        'one-sided strip is used directly',
        confidence: 'low',
      );
    }
  }

  static void _analyzeIdioms(_NimSimpleLineContext context) {
    final String line = context.line;
    final String lower = context.lower;
    if (lower.contains('.map(') && lower.contains('.filter(')) {
      context.add(
        'nim-functional-alloc-chain',
        RuleSeverity.info,
        'functional chain creates intermediate sequence allocations',
        confidence: 'low',
      );
    }
    if (line.startsWith('let ') &&
        RegExp(r'=\s*(?:\d|true|false)').hasMatch(line)) {
      context.add(
        'nim-could-be-const',
        RuleSeverity.info,
        'let with a literal value could be const',
        confidence: 'low',
      );
    }
    if (RegExp(
      r'^(?:import|from)\s+(?:os|strutils|sequtils|tables|sets|json|times)(?:\b|,)',
    ).hasMatch(line)) {
      context.add(
        'nim-std-import',
        RuleSeverity.info,
        'standard-library import should use std/ prefix',
        confidence: 'medium',
      );
    }
  }

  static void _analyzeExceptions(_NimSimpleLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    if (line == 'except:' || line.startsWith('except CatchableError')) {
      context.add(
        'nim-broad-except',
        RuleSeverity.warn,
        'broad exception handler catches too much',
      );
    }
    if (line.startsWith('except ') &&
        index + 1 < lines.length &&
        lines[index + 1].trim() == 'discard') {
      context.add(
        'nim-empty-except-body',
        RuleSeverity.warn,
        'exception handler discards the failure',
      );
    }
    if (RegExp(r'\bcast\s*\[').hasMatch(line)) {
      context.add(
        'nim-cast-usage',
        RuleSeverity.warn,
        'cast used to reinterpret types',
      );
    }
  }

  static void _analyzeDeclarations(_NimSimpleLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    if (line.startsWith('case ')) {
      final String nearby = lines.skip(index + 1).take(10).join('\n');
      if (RegExp(r'''\bof\s+["']''').hasMatch(nearby)) {
        context.add(
          'nim-case-on-string',
          RuleSeverity.info,
          'case statement branches on a string value',
          confidence: 'low',
        );
      }
    }
    final RegExpMatch? redundant = RegExp(
      r'^var\s+\w+\s*:\s*(int|string|float\w*|bool)\s*=\s*(0|""|0\.0|false)$',
    ).firstMatch(line);
    if (redundant != null) {
      context.add(
        'nim-redundant-type-init',
        RuleSeverity.info,
        'variable has redundant explicit default initialization',
        confidence: 'low',
      );
    }
    final RegExpMatch? namedProc = RegExp(
      r'^(?:proc|func)\s+([A-Za-z_]\w*)_([A-Za-z_]\w*)\s*\(\s*\w+\s*:\s*(?:var\s+|ref\s+|ptr\s+)?([A-Za-z_]\w*)',
    ).firstMatch(line);
    if (namedProc != null &&
        namedProc.group(1)!.toLowerCase() ==
            namedProc.group(3)!.toLowerCase()) {
      context.add(
        'nim-type-prefix-proc-naming',
        RuleSeverity.info,
        'proc name repeats the first parameter type prefix',
        confidence: 'low',
      );
    }
  }

  static void _analyzeLoops(_NimSimpleLineContext context) {
    final String line = context.line;
    if (RegExp(r'^while\s+\w+\s*<\s*\w+\.len').hasMatch(line)) {
      context.add(
        'nim-while-index-loop',
        RuleSeverity.info,
        'index-controlled while loop can use iteration',
      );
    }
    if (line.startsWith('return ') && !line.startsWith('return if ')) {
      context.add(
        'nim-return-instead-of-result',
        RuleSeverity.info,
        'return at end of proc could use the result variable',
        confidence: 'low',
      );
    }
    if (line.contains('not ') && line.contains('.isNil')) {
      context.add(
        'nim-negated-isnil',
        RuleSeverity.info,
        'negated isNil expression',
      );
    }
  }

  static void _analyzeTypes(_NimSimpleLineContext context) {
    final String line = context.line;
    if (line.startsWith('method ')) {
      context.add(
        'nim-method-dispatch',
        RuleSeverity.info,
        'runtime method dispatch used',
      );
    }
    if (RegExp(r'=\s*object\s+of\s+').hasMatch(line) &&
        !line.contains('ref object')) {
      context.add(
        'nim-nonref-inheritance',
        RuleSeverity.warn,
        'non-ref object inheritance used',
      );
    }
  }

  static void _analyzeCallables(_NimSimpleLineContext context) {
    final String line = context.line;
    final RegExpMatch? callable = RegExp(
      r'^(?:proc|func|method)\s+[^\(]+\(([^)]*)\)',
    ).firstMatch(line);
    if (callable != null && ','.allMatches(callable.group(1)!).length >= 5) {
      final int parameterCount = ','.allMatches(callable.group(1)!).length + 1;
      context.add(
        'nim-too-many-parameters',
        RuleSeverity.warn,
        'proc has $parameterCount parameters (more than 6)',
      );
    }
  }

  static void _analyzeContracts(_NimSimpleLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    if (RegExp(r'^(?:proc|func)\s+\w+\*').hasMatch(line) &&
        !line.contains('{.raises:')) {
      context.add(
        'nim-missing-raises',
        RuleSeverity.info,
        'exported proc lacks {.raises.} contract',
        confidence: 'low',
      );
    }
    if (RegExp(r'^(?:proc|func)\s+\w+\*').hasMatch(line) &&
        (index == 0 || !lines[index - 1].trim().startsWith('##'))) {
      context.add(
        'nim-missing-doc',
        RuleSeverity.info,
        'exported proc or func lacks a doc comment',
        confidence: 'low',
      );
    }
    if (line.contains('raise newException(Exception')) {
      context.add(
        'nim-generic-exception-raise',
        RuleSeverity.warn,
        'generic Exception raised',
      );
    }
  }

  static void _analyzeSecurity(_NimSimpleLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    if (RegExp(
          r'\b(?:execCmd|execShellCmd|execProcess|startProcess)\s*\(',
        ).hasMatch(line) &&
        (line.contains('&') || line.contains(r'$'))) {
      context.add(
        'nim-exec-dynamic-command',
        RuleSeverity.warn,
        'process execution uses a dynamically built command',
      );
    }
    if (RegExp(r'\bsleep\s*\(').hasMatch(line) &&
        lines
            .take(index)
            .toList()
            .reversed
            .take(80)
            .any(
              (String previous) => RegExp(
                r'^(?:proc|func)\s+(?:update|draw|tick)',
              ).hasMatch(previous.trim()),
            )) {
      context.add(
        'nim-sleep-in-game-loop',
        RuleSeverity.warn,
        'sleep used in game-loop function',
      );
    }
  }
}

final class _NimSimpleLineContext {
  _NimSimpleLineContext({
    required this.path,
    required this.lines,
    required this.index,
    required this.raw,
    required this.line,
  });

  final String path;
  final List<String> lines;
  final int index;
  final String raw;
  final String line;
  final List<Finding> result = <Finding>[];
  String get lower => line.toLowerCase();

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
}
