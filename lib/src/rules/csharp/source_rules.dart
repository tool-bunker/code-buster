// C# source heuristics share comment, string, and declaration handling, so their focused checks live in one scanner.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Executes the legacy C# rule family outside the language adapter.
final class CSharpRuleAnalysis {
  /// Emits explicitly enabled C# rules, matching Code Buster's opt-in policy.
  List<Finding> findings(
    Map<String, String> sources,
    AnalysisConfig config, {
    Set<String> enabledIds = const <String>{},
  }) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final _CSharpFindingContext context = _CSharpFindingContext(
        path: entry.key,
        lines: entry.value.split('\n'),
        config: config,
        result: result,
        enabledIds: enabledIds,
      );
      for (var index = 0; index < context.lines.length; index++) {
        context.index = index;
        context.prepareLine();
        _analyzeStructure(context);
        _analyzeRuntime(context);
        _analyzeLegacyApis(context);
        _analyzeSecurity(context);
      }
    }
    return result;
  }

  static void _analyzeStructure(_CSharpFindingContext context) {
    final String line = context.line;
    if (line.startsWith('namespace ') && !line.endsWith(';')) {
      context.namespaceDepth = 1;
      context.add(
        'cs-file-scoped-namespace',
        RuleSeverity.info,
        'block-scoped namespace used in C# file',
      );
    } else if (context.namespaceDepth > 0) {
      context.namespaceDepth +=
          '{'.allMatches(context.raw).length -
          '}'.allMatches(context.raw).length;
      if (context.namespaceDepth > 0 && _isUsingDirective(line)) {
        context.add(
          'cs-using-inside-namespace',
          RuleSeverity.warn,
          'using directive appears inside a namespace',
        );
      }
    }
    if (_catchesSystemException(line)) {
      context.add(
        'cs-catch-system-exception',
        RuleSeverity.warn,
        'catch block catches System.Exception',
      );
    }
    if (_runtimeType.hasMatch(context.legacyApiLine)) {
      context.add(
        'cs-runtime-type-alias',
        RuleSeverity.info,
        'runtime type name used instead of C# keyword',
      );
    }
    if (_usesNonShortCircuitBoolean(line)) {
      context.add(
        'cs-non-short-circuit-bool',
        RuleSeverity.warn,
        'boolean condition uses non-short-circuit operator',
      );
    }
    if (line.startsWith('catch') && _emptyBlock(context.lines, context.index)) {
      context.add('cs-empty-catch', RuleSeverity.warn, 'catch block is empty');
    }
    _analyzeLoop(context);
  }

  static bool _isUsingDirective(String line) {
    if (!line.startsWith('using ') ||
        !line.endsWith(';') ||
        line.startsWith('using (')) {
      return false;
    }
    final int equals = line.indexOf('=');
    if (equals == -1) {
      return true;
    }
    final String alias = line.substring('using '.length, equals).trim();
    return RegExp(r'^[A-Za-z_]\w*$').hasMatch(alias);
  }

  static void _analyzeLoop(_CSharpFindingContext context) {
    if (RegExp(r'^(?:for|foreach)\b').hasMatch(context.line)) {
      context.loopDepth++;
    }
    if (_concatenatesInLoop(context)) {
      context.add(
        'cs-string-concat-loop',
        RuleSeverity.info,
        'possible string concatenation inside loop',
      );
    }
    if (context.loopDepth > 0 && context.line == '}') context.loopDepth--;
  }

  static void _analyzeRuntime(_CSharpFindingContext context) {
    final RegExpMatch? readonlyHttpClient = _readonlyHttpClientField.firstMatch(
      context.legacyApiLine,
    );
    if (readonlyHttpClient != null) {
      context.readonlyHttpClientFields.add(readonlyHttpClient.group(1)!);
    }
    final String line = context.line;
    if (line.contains(' = new ') && line.contains('delegate')) {
      context.add(
        'cs-explicit-delegate-new',
        RuleSeverity.info,
        'explicit delegate construction can use concise syntax',
      );
    }
    final String commentFreeLine = context.legacyApiLine;
    if (commentFreeLine.contains('async void ') &&
        !_asyncVoidEventHandler.hasMatch(commentFreeLine) &&
        !_asyncVoidOverride.hasMatch(commentFreeLine)) {
      context.add('cs-async-void', RuleSeverity.warn, 'async void method used');
    }
    if (_synchronouslyWaits(line)) {
      context.add(
        'cs-sync-over-async',
        RuleSeverity.warn,
        'synchronous wait on async work',
      );
    }
    if (line.contains('Thread.Sleep(')) {
      context.add('cs-thread-sleep', RuleSeverity.info, 'Thread.Sleep used');
    }
    if (_usesLocalTime(line)) {
      context.add(
        'cs-datetime-now',
        RuleSeverity.info,
        'local wall-clock time used',
      );
    }
    if (line.contains('new HttpClient(') &&
        !_constructsSharedHttpClient(context, line)) {
      context.add(
        'cs-new-httpclient',
        RuleSeverity.info,
        'HttpClient constructed directly',
      );
    }
  }

  static void _analyzeLegacyApis(_CSharpFindingContext context) {
    final String line = context.line;
    final String legacyApiLine = context.legacyApiLine;
    if (_usesBinaryFormatter(legacyApiLine)) {
      context.add(
        'cs-binaryformatter',
        RuleSeverity.warn,
        'BinaryFormatter API referenced',
      );
    }
    if (_usesRemoting(legacyApiLine)) {
      context.add(
        'cs-remoting-api',
        RuleSeverity.warn,
        '.NET Remoting API referenced',
      );
    }
    if (_usesDcom(legacyApiLine)) {
      context.add(
        'cs-dcom-api',
        RuleSeverity.info,
        'COM/DCOM interop surface referenced',
      );
    }
    if (line.contains('AllowPartiallyTrustedCallers')) {
      context.add(
        'cs-aptca-attribute',
        RuleSeverity.warn,
        'AllowPartiallyTrustedCallers attribute used',
      );
    }
    if (!line.startsWith('//') && _casApi.hasMatch(line)) {
      context.add(
        'cs-cas-api',
        RuleSeverity.info,
        'Code Access Security API referenced',
      );
    }
    if (_publicPInvoke(context)) {
      context.add(
        'cs-public-pinvoke',
        RuleSeverity.info,
        'public native interop entry point exposed',
      );
    }
  }

  static void _analyzeSecurity(_CSharpFindingContext context) {
    if (_startsProcessWithInput(context.line)) {
      context.add(
        'cs-process-start-input',
        RuleSeverity.warn,
        'external process is started with apparent user-controlled input',
      );
    }
    if (_containsHardcodedSecret(context)) {
      context.add(
        'cs-hardcoded-secret',
        RuleSeverity.warn,
        'possible hardcoded secret',
      );
    }
    if (!context.line.startsWith('//') && _weakCrypto.hasMatch(context.line)) {
      context.add(
        'cs-weak-crypto',
        RuleSeverity.warn,
        'weak cryptography API referenced',
      );
    }
    if (_usesRandomForSecurity(context)) {
      context.add(
        'cs-random-security',
        RuleSeverity.warn,
        'System.Random appears used for security-sensitive value',
      );
    }
    if (_buildsSqlString(context)) {
      context.add(
        'cs-sql-string-build',
        RuleSeverity.warn,
        'SQL appears to be built with interpolation/concatenation',
      );
    }
  }

  static bool _catchesSystemException(String line) =>
      line.startsWith('catch (Exception') ||
      line.startsWith('catch (System.Exception');
  static bool _usesNonShortCircuitBoolean(String line) {
    if (!RegExp(r'^(?:if|while)\s*\(').hasMatch(line) ||
        !_hasTopLevelNonShortCircuitOperator(line)) {
      return false;
    }
    return !_numericBitwiseOperand.hasMatch(line) &&
        !_bitwiseResultComparison.hasMatch(line);
  }

  static bool _hasTopLevelNonShortCircuitOperator(String line) {
    final String code = _stripStrings(line);
    var depth = 0;
    for (var index = code.indexOf('('); index < code.length; index++) {
      final int character = code.codeUnitAt(index);
      if (character == 40) {
        depth++;
        continue;
      }
      if (character == 41) {
        depth--;
        continue;
      }
      if (depth != 1 || (character != 38 && character != 124)) continue;
      final bool doubledBefore =
          index > 0 && code.codeUnitAt(index - 1) == character;
      final bool doubledAfter =
          index + 1 < code.length && code.codeUnitAt(index + 1) == character;
      if (!doubledBefore && !doubledAfter) return true;
    }
    return false;
  }

  static bool _concatenatesInLoop(_CSharpFindingContext context) {
    if (context.loopDepth <= 0 || !context.line.contains(' + ')) {
      return false;
    }

    String? target;
    final int plusEquals = context.line.indexOf(' += ');
    if (plusEquals >= 0) {
      final int rawPlusEquals = context.raw.indexOf('+=');
      final String rawRight = rawPlusEquals < 0
          ? ''
          : context.raw.substring(rawPlusEquals + 2);
      if (RegExp(r'''(?:@|\$@|@\$|\$)?"''').hasMatch(rawRight)) {
        return true;
      }
      final String candidate = context.line.substring(0, plusEquals).trim();
      if (RegExp(r'^[A-Za-z_]\w*$').hasMatch(candidate)) {
        target = candidate;
      }
    } else {
      target = RegExp(
        r'^([A-Za-z_]\w*)\s*=\s*\1\s*\+',
      ).firstMatch(context.line)?.group(1);
    }
    if (target == null) return false;

    final RegExp stringDeclaration = RegExp(
      r'\bstring\s+' + RegExp.escape(target) + r'\b',
    );
    return context.lines
        .take(context.index)
        .any((String line) => stringDeclaration.hasMatch(line));
  }

  static bool _synchronouslyWaits(String line) {
    final String code = line.split('//').first;
    return !_synchronizationEventWait.hasMatch(code) &&
        _synchronousWait.hasMatch(code);
  }

  static bool _usesLocalTime(String line) =>
      line.contains('DateTime.Now') || line.contains('DateTimeOffset.Now');
  static bool _usesBinaryFormatter(String line) =>
      line.contains('BinaryFormatter') ||
      line.contains('System.Runtime.Serialization.Formatters.Binary');
  static bool _usesRemoting(String line) =>
      line.contains('System.Runtime.Remoting') ||
      line.contains('RemotingConfiguration') ||
      line.contains('MarshalByRefObject');
  static bool _usesDcom(String line) =>
      line.contains('System.EnterpriseServices') ||
      line.contains('ServicedComponent') ||
      line.contains('[ComImport') ||
      line.contains('CoCreateInstance');
  static bool _publicPInvoke(_CSharpFindingContext context) =>
      (context.line.contains('[DllImport') ||
          context.line.contains('[LibraryImport')) &&
      _nextNonBlank(
        context.lines,
        context.index + 1,
      ).trim().startsWith('public') &&
      _isInExternallyVisibleType(context.lines, context.index);

  static bool _isInExternallyVisibleType(List<String> lines, int end) {
    final List<({int depth, bool visible})> scopes =
        <({int depth, bool visible})>[];
    bool? pendingTypeVisibility;
    var depth = 0;

    for (var index = 0; index <= end; index++) {
      final String code = _stripStrings(lines[index].split('//').first).trim();
      final RegExpMatch? declaration = _typeDeclaration.firstMatch(code);
      if (declaration != null) {
        final String modifiers = declaration.group(1) ?? '';
        final bool restricted = RegExp(
          r'\b(?:private|internal|file)\b',
        ).hasMatch(modifiers);
        pendingTypeVisibility =
            !restricted &&
            RegExp(r'\b(?:public|protected)\b').hasMatch(modifiers);
      }

      for (final int character in code.codeUnits) {
        if (character == 123) {
          depth++;
          if (pendingTypeVisibility != null) {
            scopes.add((depth: depth, visible: pendingTypeVisibility));
            pendingTypeVisibility = null;
          }
        } else if (character == 125) {
          if (scopes.isNotEmpty && scopes.last.depth == depth) {
            scopes.removeLast();
          }
          depth--;
        }
      }
      if (pendingTypeVisibility != null && code.contains(';')) {
        pendingTypeVisibility = null;
      }
    }

    return scopes.isNotEmpty && scopes.every((scope) => scope.visible);
  }

  static bool _startsProcessWithInput(String line) =>
      line.contains('Process.Start') &&
      (line.contains('Request.') ||
          line.contains('Console.ReadLine') ||
          line.contains('args['));
  static bool _containsHardcodedSecret(_CSharpFindingContext context) {
    final RegExpMatch? assignment = _literalAssignment.firstMatch(context.raw);
    if (assignment == null) return false;
    final String identifier = assignment.group(1)!;
    final String literal = assignment.group(2)!;
    final String normalizedIdentifier = identifier
        .replaceAll(RegExp('[^A-Za-z0-9]'), '')
        .toLowerCase();
    final String normalizedLiteral = literal
        .replaceAll(RegExp('[^A-Za-z0-9]'), '')
        .toLowerCase();
    return literal.trim().isNotEmpty &&
        _secretIdentifier.hasMatch(identifier) &&
        normalizedLiteral != normalizedIdentifier &&
        !_isPlaceholderSecretLiteral(normalizedLiteral) &&
        !_isLexicalTokenLiteral(
          identifier,
          literal,
          normalizedIdentifier,
          normalizedLiteral,
        ) &&
        !_nonCredentialKey.hasMatch(identifier) &&
        !_uriLiteral.hasMatch(literal) &&
        !_symbolicSecretLiteral.hasMatch(literal) &&
        !context.lowerRaw.contains('environment.getenvironmentvariable') &&
        !context.lowerRaw.contains('configuration[');
  }

  static bool _usesRandomForSecurity(_CSharpFindingContext context) =>
      (context.line.contains('new Random(') ||
          context.line.contains('Random.Shared')) &&
      _secretIdentifier.hasMatch(context.raw);
  static bool _buildsSqlString(_CSharpFindingContext context) {
    final String raw = context.raw;
    if (!RegExp(
      r'\b\w*(?:sql|query|command)\w*\s*=\s*(?:\$@?|@\$?)?"[^"]*\b(?:select|insert|update|delete)\s',
      caseSensitive: false,
    ).hasMatch(raw)) {
      return false;
    }
    if ((raw.contains(r'$"') || raw.contains(r'$@"') || raw.contains(r'@$"')) &&
        RegExp(r'\{[^{}]+\}').hasMatch(raw)) {
      return !_onlySafeNumericSqlInterpolation(context);
    }
    if (!raw.contains('+')) return false;
    final String expression = _stripStrings(raw).split('=').skip(1).join('=');
    return RegExp(
      r'(?:\+\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*\+)',
    ).hasMatch(expression);
  }

  static bool _onlySafeNumericSqlInterpolation(_CSharpFindingContext context) {
    final List<RegExpMatch> expressions = RegExp(
      r'(?<!\{)\{([^{}]+)\}(?!\})',
    ).allMatches(context.raw).toList(growable: false);
    if (expressions.isEmpty) return false;

    return expressions.every((RegExpMatch match) {
      final String expression = match.group(1)!.trim();
      if (_numericCastExpression.hasMatch(expression)) return true;
      if (!RegExp(r'^[A-Za-z_]\w*$').hasMatch(expression)) return false;

      final int first = context.index > 80 ? context.index - 80 : 0;
      for (var previous = context.index - 1; previous >= first; previous--) {
        final String declaration = context.lines[previous];
        final String name = RegExp.escape(expression);
        if (RegExp(
          '\\b(?:const\\s+)?(?:s?byte|u?short|u?int|u?long|float|double|decimal)\\s+$name\\b',
        ).hasMatch(declaration)) {
          return true;
        }
        final RegExpMatch? inferred = RegExp(
          '\\bvar\\s+$name\\s*=\\s*([^;]+)',
        ).firstMatch(declaration);
        if (inferred != null) {
          final String value = inferred.group(1)!.trim();
          return _numericLiteral.hasMatch(value) ||
              RegExp(r'\.Ticks\b').hasMatch(value);
        }
      }
      return false;
    });
  }

  static bool _constructsSharedHttpClient(
    _CSharpFindingContext context,
    String line,
  ) {
    if (_staticHttpClientMember.hasMatch(line)) return true;
    final RegExpMatch? assignment = _httpClientAssignment.firstMatch(line);
    return assignment != null &&
        context.readonlyHttpClientFields.contains(assignment.group(1));
  }

  static bool _emptyBlock(List<String> lines, int start) {
    var index = start + 1;
    while (index < lines.length &&
        (lines[index].trim().isEmpty || lines[index].trim() == '{')) {
      index++;
    }
    return index < lines.length && lines[index].trim() == '}';
  }

  static String _nextNonBlank(List<String> lines, int start) {
    for (var index = start; index < lines.length; index++) {
      if (lines[index].trim().isNotEmpty) return lines[index];
    }
    return '';
  }

  static String _stripStrings(String line) => line.replaceAll(
    RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' '''.trim()),
    '',
  );
  static final RegExp _asyncVoidEventHandler = RegExp(
    r'\basync\s+void\s+[A-Za-z_]\w*\s*\(\s*object\??\s+sender\s*,\s*'
    r'(?:[A-Za-z_]\w*\.)*(?:[A-Za-z_]\w*)?EventArgs\??\s+[A-Za-z_]\w*\s*\)',
  );
  static final RegExp _asyncVoidOverride = RegExp(
    r'\boverride\s+async\s+void\b',
  );
  static final RegExp _staticHttpClientMember = RegExp(
    r'^(?=[^=]*\bstatic\b)'
    r'(?:(?:public|protected|internal|private|new|static|readonly|volatile|unsafe)\s+)+'
    r'(?:System\.Net\.Http\.)?HttpClient\??\s+[A-Za-z_]\w*\s*'
    r'(?:\{[^}]*\}\s*)?=\s*new\s+HttpClient\s*\(',
  );
  static final RegExp _readonlyHttpClientField = RegExp(
    r'\breadonly\s+(?:System\.Net\.Http\.)?HttpClient\??\s+([A-Za-z_]\w*)\s*;',
  );
  static final RegExp _synchronizationEventWait = RegExp(
    r'(?:\b|\.)[A-Za-z_]\w*Event\.Wait\s*\(\s*\)',
  );
  static final RegExp _httpClientAssignment = RegExp(
    r'^(?:this\.)?([A-Za-z_]\w*)\s*=\s*new\s+HttpClient\s*\(',
  );
  static final RegExp _typeDeclaration = RegExp(
    r'^(?:\[[^\]]+\]\s*)*((?:(?:public|protected|internal|private|file|new|static|abstract|sealed|partial|readonly|ref)\s+)*)'
    r'(?:class|struct|interface|record(?:\s+(?:class|struct))?)\s+[A-Za-z_]\w*',
  );
  static final RegExp _numericBitwiseOperand = RegExp(
    r'(?:0[xX][0-9A-Fa-f]+|\b\d+)(?:[uUlL]+)?\s*[&|]|'
    r'[&|]\s*(?:0[xX][0-9A-Fa-f]+|\d+)(?:[uUlL]+\b)?',
  );
  static final RegExp _bitwiseResultComparison = RegExp(
    r'\([^;\n]*\s[&|]\s[^;\n]*\)\s*(?:==|!=|<=|>=|<|>)\s*(?!true\b|false\b)',
  );
  static final RegExp _numericCastExpression = RegExp(
    r'^\((?:s?byte|u?short|u?int|u?long|float|double|decimal)\)\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$',
  );
  static final RegExp _numericLiteral = RegExp(
    r'^[+-]?\d[\d_]*(?:\.\d[\d_]*)?[fFdDmMuUlL]*$',
  );
  static final RegExp _synchronousWait = RegExp(
    r'\.Result\b(?!\s*=(?!=))|\.Wait\s*\(\s*\)|\.GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\(\s*\)',
  );
  static final RegExp _runtimeType = RegExp(
    r'\bSystem\.(?:String|Int32|Boolean|Object|Void)\b',
  );
  static final RegExp _casApi = RegExp(
    r'\b(?:CodeAccessPermission|SecurityPermission|PermissionSet)\b',
  );
  static final RegExp _weakCrypto = RegExp(
    r'\bHashAlgorithmName\.(?:MD5|SHA1)\b|\b(?:MD5|SHA1|DES|TripleDES|RC2|RijndaelManaged)\b\s*(?:\(|\.Create\b)',
  );
  static final RegExp _literalAssignment = RegExp(
    r'\b([A-Za-z_]\w*)\s*=\s*(?:@|\$@|@\$)?"([^"]*)"',
  );
  static final RegExp _uriLiteral = RegExp(r'^[A-Za-z][A-Za-z0-9+.-]*://');
  static final RegExp _symbolicSecretLiteral = RegExp(
    r'^(?:[A-Z][A-Z0-9_]*|[a-z0-9]+(?:_[a-z0-9]+)+|[a-z]+-\d+(?:-[a-z0-9]+)*|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+|<[A-Za-z0-9_:-]+>|\[[A-Za-z0-9_:-]+\])$',
  );
  static bool _isLexicalTokenLiteral(
    String identifier,
    String literal,
    String normalizedIdentifier,
    String normalizedLiteral,
  ) {
    if (!identifier.toLowerCase().endsWith('token')) return false;

    final String prefix = normalizedIdentifier.substring(
      0,
      normalizedIdentifier.length - 'token'.length,
    );
    return (prefix.isNotEmpty &&
            (prefix == normalizedLiteral ||
                prefix.endsWith(normalizedLiteral))) ||
        RegExp(r'^[A-Z][A-Za-z0-9]*$').hasMatch(literal) ||
        RegExp(r'\{\d+\}').hasMatch(literal) ||
        (literal.startsWith('<') && literal.endsWith('>'));
  }

  static const Set<String> _placeholderSecretLiterals = <String>{
    'password',
    'changeme',
    'yoursecret',
    'yourapikey',
    'placeholder',
    'example',
    'test',
  };
  static final RegExp _placeholderSecretPattern = RegExp(
    r'^(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)$',
  );
  static bool _isPlaceholderSecretLiteral(String normalizedLiteral) =>
      _placeholderSecretLiterals.contains(normalizedLiteral) ||
      _placeholderSecretPattern.hasMatch(normalizedLiteral);
  static final RegExp _secretIdentifier = RegExp(
    r'(?:^|_)(?:token|secret|password|passwd|api_?key|nonce|salt)(?:$|_)|(?:access|auth|bearer|refresh|session|jwt|api|client|identity|security|oauth)token$|(?:secret|password|passwd|apikey|nonce|salt)$',
    caseSensitive: false,
  );
  static final RegExp _nonCredentialKey = RegExp(
    r'(?:Map|Preference|Package|Action|Type|Path|Error|Width|Height|Quality|Configuration|Setting|Name|Id|Url|Uri|File|Directory|Certificate)(?:Key|Token|Secret|Password)?$|^HeaderName\w*$',
    caseSensitive: false,
  );
}

final class _CSharpFindingContext {
  _CSharpFindingContext({
    required this.path,
    required this.lines,
    required this.config,
    required this.result,
    required this.enabledIds,
  });

  final String path;
  final List<String> lines;
  final AnalysisConfig config;
  final List<Finding> result;
  int index = 0;
  final Set<String> enabledIds;
  final Set<String> readonlyHttpClientFields = <String>{};
  int namespaceDepth = 0;
  int loopDepth = 0;
  bool _insideBlockComment = false;
  int? _stringQuote;
  bool _verbatimString = false;
  String _commentFreeRaw = '';

  String get raw => lines[index];
  String get line => CSharpRuleAnalysis._stripStrings(raw).trim();
  String get lowerRaw => raw.toLowerCase();
  String get legacyApiLine =>
      CSharpRuleAnalysis._stripStrings(_commentFreeRaw).trim();

  void prepareLine() {
    final String source = raw;
    final StringBuffer output = StringBuffer();

    for (var offset = 0; offset < source.length; offset++) {
      final int character = source.codeUnitAt(offset);
      final int? next = offset + 1 < source.length
          ? source.codeUnitAt(offset + 1)
          : null;

      if (_insideBlockComment) {
        if (character == 42 && next == 47) {
          _insideBlockComment = false;
          offset++;
        }
        continue;
      }

      if (_stringQuote != null) {
        output.writeCharCode(character);
        if (!_verbatimString && character == 92 && next != null) {
          output.writeCharCode(next);
          offset++;
          continue;
        }
        if (character != _stringQuote) continue;
        if (_verbatimString && next == _stringQuote) {
          output.writeCharCode(next!);
          offset++;
        } else {
          _stringQuote = null;
          _verbatimString = false;
        }
        continue;
      }

      if (character == 47 && next == 47) break;
      if (character == 47 && next == 42) {
        _insideBlockComment = true;
        offset++;
        continue;
      }
      if (character == 34 || character == 39) {
        _stringQuote = character;
        _verbatimString =
            character == 34 &&
            offset > 0 &&
            source.codeUnitAt(offset - 1) == 64;
      }
      output.writeCharCode(character);
    }

    if (!_verbatimString) _stringQuote = null;
    _commentFreeRaw = output.toString();
  }

  void add(String id, RuleSeverity severity, String message) {
    if (!enabledIds.contains(id) && !config.severityOverrides.containsKey(id)) {
      return;
    }
    result.add(
      Finding(
        code: id,
        severity: severity,
        path: path,
        line: index + 1,
        endLine: index + 1,
        message: message,
        confidence: 'medium',
        why: id == 'cs-async-void'
            ? 'async void exceptions cannot be awaited/caught by callers and complicate testing, except for event handlers.'
            : 'This C# construct weakens clarity, reliability, or security.',
        suggestion: id == 'cs-async-void'
            ? 'Return Task/ValueTask unless this is a UI/event handler with documented intent.'
            : 'Use the safer modern .NET alternative described by the rule.',
      ),
    );
  }
}

/// One independently registered C# rule backed by the shared source scan.
final class CSharpSourceRule extends SelfContainedRule {
  /// Creates a rule with canonical metadata beside its execution contract.
  CSharpSourceRule({
    required String id,
    required RuleSeverity severity,
    required String group,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title: 'Review ${id.substring(3).replaceAll('-', ' ')}',
           why: id == 'cs-async-void'
               ? 'async void exceptions cannot be awaited/caught by callers and complicate testing, except for event handlers.'
               : 'This C# construct can weaken clarity, reliability, or security.',
           suggestion: id == 'cs-async-void'
               ? 'Return Task/ValueTask unless this is a UI/event handler with documented intent.'
               : 'Use the safer modern .NET alternative described by the rule.',
           languages: const <String>['csharp'],
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => CSharpRuleAnalysis()
      .findings(
        context.sources,
        context.config,
        enabledIds: <String>{metadata.id},
      )
      .where((Finding finding) => finding.code == metadata.id)
      .map(
        (Finding finding) => context.report(
          metadata: metadata,
          path: finding.path,
          line: finding.line,
          endLine: finding.endLine,
          message: finding.message,
          confidence: finding.confidence,
          relatedFiles: finding.relatedFiles,
          snippet: finding.snippet,
          codeFlow: finding.codeFlow,
        ),
      );
}
