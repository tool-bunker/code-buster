// Stateful Nim patterns involving hooks, protocol code, allocation, and serialization need more context than the simple lexical pack.

import '../../core/models.dart';
import 'canonical_nim_evidence.dart';

/// Executes stateful advanced API, hook, protocol, and serialization rules.
final class NimAdvancedLineRulePack {
  bool _inExportedRefObject = false;
  int _objectIndent = -1;

  /// Generic hook declarations encountered in the file.
  int genericHookCount = 0;

  /// Whether the file imports another module.
  bool hasImport = false;

  /// Whether an exported generic serialization wrapper was found.
  bool hasGenericSerializationWrapper = false;

  /// Number of public JSON-oriented API declarations.
  int jsonApiCount = 0;

  /// Declared distinct types.
  final Set<String> distinctTypes = <String>{};

  /// Types with dump or encode hooks.
  final Set<String> dumpTypes = <String>{};

  /// Types with parse or decode hooks.
  final Set<String> parseTypes = <String>{};

  /// Processes one line while retaining advanced API state for the file.
  List<Finding> analyzeLine({
    required String path,
    required String source,
    required List<String> lines,
    required int index,
    required String raw,
    required String line,
    required String lower,
    required int indent,
    required bool isTest,
    required bool mentionsWebSocket,
  }) {
    final context = _NimAdvancedLineContext(
      path: path,
      source: source,
      lines: lines,
      index: index,
      raw: raw,
      line: line,
      lower: lower,
      indent: indent,
      isTest: isTest,
      mentionsWebSocket: mentionsWebSocket,
    );
    _analyzeObjectState(context);
    _analyzeGenericHooks(context);
    _analyzePlugins(context);
    _analyzeSerialization(context);
    _analyzeProtocols(context);
    _analyzeTemplates(context);
    _analyzeApiSurface(context);
    return context.result;
  }

  void _analyzeObjectState(_NimAdvancedLineContext context) {
    final String line = context.line;
    final int indent = context.indent;
    if (_inExportedRefObject && indent <= _objectIndent) {
      _inExportedRefObject = false;
    }
    if (line.contains('* = ref object')) {
      _inExportedRefObject = true;
      _objectIndent = indent;
    } else if (_inExportedRefObject &&
        line.contains('*') &&
        RegExp(r':\s*(?:seq|Table|OrderedTable|HashSet)\[').hasMatch(line)) {
      context.add(
        'nim-public-mutable-container-field',
        RuleSeverity.info,
        'exported ref object exposes a mutable container field',
        confidence: 'low',
      );
    }
    if (line.startsWith('import ') || line.startsWith('from ')) {
      hasImport = true;
    }
  }

  void _analyzeGenericHooks(_NimAdvancedLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    final int genericOpen = line.indexOf('[');
    final int genericClose = line.indexOf(']');
    final int parameterOpen = line.indexOf('(');
    final bool genericDeclaration =
        (line.startsWith('proc ') || line.startsWith('func ')) &&
        genericOpen >= 0 &&
        genericClose > genericOpen &&
        parameterOpen > genericClose;
    final bool genericHook = genericDeclaration && line.contains('Hook');
    if (genericHook) {
      genericHookCount++;
      context.add(
        'nim-hook-too-generic',
        RuleSeverity.info,
        'generic hook proc may be too broad',
        confidence: 'low',
      );
      if (line.contains('[T]') &&
          (line.contains('seq[T]') ||
              line.contains(': T') ||
              line.contains('ref T'))) {
        context.add(
          'nim-generic-hook-same-signature',
          RuleSeverity.warn,
          'generic hook signature is likely to duplicate a library hook shape',
        );
      }
      if (line.contains('*') &&
          !(index > 0 && lines[index - 1].trim().startsWith('##')) &&
          !line.contains('##')) {
        context.add(
          'nim-generic-hook-missing-doc',
          RuleSeverity.info,
          'exported generic hook lacks overload-resolution documentation',
          confidence: 'low',
        );
      }
    }
    if (genericDeclaration &&
        line.contains('*') &&
        RegExp(
          r'tojson|dump|serialize|encode',
          caseSensitive: false,
        ).hasMatch(line)) {
      hasGenericSerializationWrapper = true;
    }
  }

  void _analyzePlugins(_NimAdvancedLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    final String lower = context.lower;
    if (line.contains('cast[') && line.contains('symAddr(')) {
      final String nearby = lines
          .skip(index > 0 ? index - 1 : 0)
          .take(3)
          .join('\n')
          .toLowerCase();
      if (!nearby.contains('nil')) {
        context.add(
          'nim-dynlib-unchecked-symbol',
          RuleSeverity.warn,
          'dynlib symbol is cast without an obvious nil check',
        );
      }
    }
    if (line.contains('loadLib(') &&
        !lines
            .skip(index)
            .take(9)
            .any(
              (String nearby) =>
                  nearby.contains('unloadLib') ||
                  nearby.contains('libs.add') ||
                  nearby.contains('handles.add') ||
                  nearby.contains('pluginLibs'),
            )) {
      context.add(
        'nim-dynlib-lifetime',
        RuleSeverity.info,
        'dynlib handle lifetime is not obvious',
        confidence: 'low',
      );
    }
    final bool pluginMention = lower.contains('plugin');
    if (pluginMention &&
        (line.contains('seq[proc') ||
            line.contains('openArray[proc') ||
            line.contains('proc ('))) {
      context.add(
        'nim-proc-only-plugin-api',
        RuleSeverity.info,
        'plugin API appears to use bare proc callbacks',
        confidence: 'low',
      );
    }
    if (pluginMention &&
        (line.contains('seq[proc') ||
            line.contains('run*: proc') ||
            line.contains('callback*: proc')) &&
        !RegExp(r'hook|runat|stage|kind').hasMatch(
          lines
              .skip(index > 8 ? index - 8 : 0)
              .take(17)
              .join('\n')
              .toLowerCase(),
        )) {
      context.add(
        'nim-plugin-hook-without-kind',
        RuleSeverity.info,
        'plugin callback has no obvious hook/stage kind',
        confidence: 'low',
      );
    }
    if (line.contains('=') &&
        RegExp(
          r'(?:context|plugincontext|ctx|config|defaults)\[',
        ).hasMatch(lower) &&
        RegExp(r'save|render|plugin|default').hasMatch(lower) &&
        !RegExp(r'haskey|mgetorput|contains').hasMatch(lower)) {
      context.add(
        'nim-default-overwrites-context',
        RuleSeverity.info,
        'context/default assignment may overwrite user configuration',
        confidence: 'low',
      );
    }
  }

  void _analyzeSerialization(_NimAdvancedLineContext context) {
    final List<Finding> result = context.result;
    final String path = context.path;
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String line = context.line;
    if ((line.startsWith('proc ') ||
            line.startsWith('func ') ||
            line.startsWith('type ')) &&
        line.contains('*') &&
        RegExp(
          r'JsonNode|JsonValue|:\s*(?:var\s+)?Value\b|seq\[Value\]|Table\[string,\s*Value\]',
        ).hasMatch(line)) {
      jsonApiCount++;
    }
    final RegExpMatch? distinct = RegExp(
      r'^(?:type\s+)?([A-Za-z_]\w*)\*?\s*=\s*distinct\s+',
    ).firstMatch(line);
    if (distinct != null) distinctTypes.add(distinct.group(1)!);
    final bool dumpHook =
        line.startsWith('proc ') &&
        (line.contains('dumpHook') ||
            line.contains('writeHook') ||
            line.contains('encodeHook'));
    final bool parseHook =
        line.startsWith('proc ') &&
        (line.contains('parseHook') ||
            line.contains('readHook') ||
            line.contains('decodeHook'));
    if (dumpHook || parseHook) {
      final int close = line.lastIndexOf(')');
      final int comma = close < 0 ? -1 : line.lastIndexOf(',', close);
      final String lastParameter = comma < 0 || close < 0
          ? ''
          : line.substring(comma + 1, close);
      final int colon = lastParameter.indexOf(':');
      final String typeName = colon < 0
          ? ''
          : lastParameter.substring(colon + 1).replaceAll('*', '').trim();
      if (typeName.isNotEmpty) {
        if (dumpHook) dumpTypes.add(typeName);
        if (parseHook) parseTypes.add(typeName);
      }
      final int open = line.indexOf('(');
      final int firstComma = line.indexOf(',', open + 1);
      final String firstParameter = open < 0 || firstComma < 0
          ? ''
          : line.substring(open + 1, firstComma);
      if (firstParameter.contains('var string')) {
        final String accumulator = firstParameter.split(':').first.trim();
        final int indent = raw.length - raw.trimLeft().length;
        final List<String> body = lines
            .skip(index + 1)
            .takeWhile(
              (String next) =>
                  next.trim().isEmpty ||
                  next.length - next.trimLeft().length > indent,
            )
            .toList();
        for (var offset = 0; offset < body.length; offset++) {
          final String inner = _withoutComment(body[offset]).trim();
          if (inner.startsWith('$accumulator =') ||
              inner.startsWith('$accumulator=')) {
            result.add(
              Finding(
                code: 'nim-hook-overwrites-accumulator',
                severity: RuleSeverity.warn,
                path: path,
                line: index + offset + 2,
                endLine: index + offset + 2,
                message: 'serialization hook assigns to accumulator string',
                confidence: 'medium',
                why:
                    'Mutable string hook parameters often contain already-serialized output; assigning replaces prior content.',
                suggestion:
                    'Append with add or a quoting/escaping helper instead of assigning to the accumulator.',
              ),
            );
          }
          if (dumpHook &&
              inner.contains('$accumulator.add') &&
              !inner.toLowerCase().contains('escape') &&
              !inner.toLowerCase().contains('quote') &&
              !inner.contains('"')) {
            result.add(
              Finding(
                code: 'nim-string-serializer-missing-quote',
                severity: RuleSeverity.info,
                path: path,
                line: index + offset + 2,
                endLine: index + offset + 2,
                message:
                    'serializer appends raw content without obvious quoting/escaping',
                confidence: 'low',
                why:
                    'String-like serialized values often need delimiter and escaping handling at the output boundary.',
                suggestion:
                    "Use the library's string quoting helper or explicitly escape and delimit string values.",
              ),
            );
          }
        }
      }
    }
  }

  void _analyzeProtocols(_NimAdvancedLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    final String lower = context.lower;
    final bool mentionsWebSocket = context.mentionsWebSocket;
    final bool httpish =
        lower.contains('header') ||
        lower.contains('connection') ||
        lower.contains('upgrade') ||
        lower.contains('websocket');
    if (httpish &&
        lower.contains('.contains(') &&
        (lower.contains('upgrade') ||
            lower.contains('websocket') ||
            lower.contains('keep-alive')) &&
        !lower.contains('split(') &&
        !lower.contains('containslist') &&
        !lower.contains('strip')) {
      context.add(
        'nim-http-header-contains',
        RuleSeverity.warn,
        'HTTP header membership check may ignore comma-separated values',
      );
    }
    if (httpish &&
        (line.contains(' == ') || line.contains(' != ')) &&
        (lower.contains('upgrade') ||
            lower.contains('websocket') ||
            lower.contains('connection')) &&
        !lower.contains('tolowerascii') &&
        !lower.contains('cmpignorecase') &&
        !lower.contains('normalize')) {
      context.add(
        'nim-http-case-sensitive-header-compare',
        RuleSeverity.info,
        'HTTP header/token comparison appears case-sensitive',
        confidence: 'low',
      );
    }
    if (mentionsWebSocket &&
        httpish &&
        lower.contains('connection') &&
        lower.contains('upgrade') &&
        (line.contains(' == ') || lower.contains('.contains(')) &&
        !lines
            .skip(index > 2 ? index - 2 : 0)
            .take(5)
            .join('\n')
            .toLowerCase()
            .contains('containslist')) {
      context.add(
        'nim-websocket-upgrade-fragile',
        RuleSeverity.warn,
        'WebSocket upgrade check may not handle `Connection: keep-alive, Upgrade`',
      );
    }
    if (httpish &&
        lower.contains('.split(') &&
        line.contains(',') &&
        !lines.skip(index).take(4).join('\n').toLowerCase().contains('strip')) {
      context.add(
        'nim-protocol-split-without-strip',
        RuleSeverity.info,
        'comma-separated protocol values are split without obvious strip/case normalization',
        confidence: 'low',
      );
    }
  }

  void _analyzeTemplates(_NimAdvancedLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String line = context.line;
    if (line.startsWith('template ') && line.contains('*')) {
      final bool documented =
          index > 0 && lines[index - 1].trimLeft().startsWith('##');
      if (!documented && !line.contains('##')) {
        context.add(
          'nim-exported-template-missing-doc',
          RuleSeverity.info,
          'exported template lacks a doc comment',
          confidence: 'low',
        );
      }
      if (line.contains('body: untyped') || line.contains('body: typed')) {
        final int indent = raw.length - raw.trimLeft().length;
        final List<String> body = lines
            .skip(index + 1)
            .takeWhile(
              (String next) =>
                  next.trim().isEmpty ||
                  next.length - next.trimLeft().length > indent,
            )
            .toList();
        final bool executesBody = body.any(
          (String next) => next.trim() == 'body',
        );
        final bool mutatesState = body.any((String next) {
          final String trimmed = next.trim();
          return trimmed.contains('.') &&
              trimmed.contains(' = ') &&
              !trimmed.startsWith('let ') &&
              !trimmed.startsWith('var ') &&
              !trimmed.startsWith('const ');
        });
        final bool restores = body.any(
          (String next) =>
              next.trim().startsWith('try:') ||
              next.trim().startsWith('finally:') ||
              next.trim().startsWith('defer:'),
        );
        if (executesBody && mutatesState) {
          context.add(
            'nim-template-body-state-mutation',
            restores ? RuleSeverity.info : RuleSeverity.warn,
            'template executes body while mutating shared state',
          );
          if (!restores) {
            context.add(
              'nim-state-restore-without-finally',
              RuleSeverity.warn,
              'state is changed around template body without defer/finally',
            );
          }
        }
      }
    }
  }

  void _analyzeApiSurface(_NimAdvancedLineContext context) {
    final List<Finding> result = context.result;
    final String path = context.path;
    final String source = context.source;
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    final String lower = context.lower;
    final bool isTest = context.isTest;
    if (lower.contains('.len') &&
        _withoutStringLiterals(line).contains('/') &&
        !lower.contains('max(1') &&
        !lines
            .skip(index > 5 ? index - 5 : 0)
            .take(8)
            .any(
              (String nearby) =>
                  RegExp(r'len\s*(?:==|!=|>)\s*0').hasMatch(nearby),
            )) {
      context.add(
        'nim-divide-by-len-without-empty-check',
        RuleSeverity.warn,
        'division by collection length without nearby empty guard',
      );
    }
    if (isTest &&
        (lower.contains('doassert') ||
            lower.contains('check ') ||
            lower.contains('assert ')) &&
        lower.contains(' == ') &&
        _floatLiteral.hasMatch(_withoutStringLiterals(lower))) {
      context.add(
        'nim-float-test-exact-equality',
        RuleSeverity.info,
        'test appears to use exact equality for floating-point result',
        confidence: 'low',
      );
    }
    if ((line.startsWith('proc ') || line.startsWith('func ')) &&
        line.contains('*') &&
        lower.contains('openarray') &&
        (source.contains('.len') || source.contains('[0]')) &&
        !source.toLowerCase().contains('empty') &&
        !source.contains('[]')) {
      result.add(
        Finding(
          code: 'nim-openarray-missing-empty-test',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message:
              'exported openArray API has no obvious empty-input coverage nearby',
          confidence: 'low',
          why:
              'openArray APIs should define behavior for empty input explicitly.',
          suggestion:
              'Add tests/docs for empty input and either reject it or return an explicit empty result.',
        ),
      );
    }
  }

  static final RegExp _floatLiteral = RegExp(r'(?:\d\.\d|\bnan\b|\binf\b)');

  String _withoutStringLiterals(String line) {
    final StringBuffer code = StringBuffer();
    var quote = '';
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final String character = line[index];
      if (quote.isEmpty) {
        if (character == '"' || character == "'") {
          quote = character;
          code.write(' ');
        } else {
          code.write(character);
        }
        continue;
      }

      code.write(' ');
      if (escaped) {
        escaped = false;
      } else if (character == r'\') {
        escaped = true;
      } else if (character == quote) {
        quote = '';
      }
    }
    return code.toString();
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

final class _NimAdvancedLineContext {
  _NimAdvancedLineContext({
    required this.path,
    required this.source,
    required this.lines,
    required this.index,
    required this.raw,
    required this.line,
    required this.lower,
    required this.indent,
    required this.isTest,
    required this.mentionsWebSocket,
  });

  final String path;
  final String source;
  final List<String> lines;
  final int index;
  final String raw;
  final String line;
  final String lower;
  final int indent;
  final bool isTest;
  final bool mentionsWebSocket;
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
}
