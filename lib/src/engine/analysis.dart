// Shared analysis passes such as complexity, duplication, flags, and repository structure operate here after language parsing is complete.

import 'dart:io';
import 'dart:math' as math;

import 'package:path/path.dart' as path;

import '../core/models.dart';
import '../core/regexp_cache.dart';
import '../discovery/discovery.dart';

/// A language adapter-provided function body for complexity analysis.
final class FunctionSource {
  /// Creates source metadata for one function-like block.
  const FunctionSource({
    required this.path,
    required this.name,
    required this.line,
    required this.source,
    int? endLine,
  }) : _endLine = endLine;

  /// Project-relative source path.
  final String path;

  /// Function name.
  final String name;

  /// One-based declaration line.
  final int line;

  /// Complete function source.
  final String source;

  final int? _endLine;

  /// One-based inclusive end line derived from [source] unless supplied.
  int get endLine => _endLine ?? line + '\n'.allMatches(source).length;
}

/// Shared lexical call and reference index for repository-wide YAGNI rules.
final class YagniCallIndex {
  /// Indexes function bodies once for all call-site-based YAGNI rules.
  YagniCallIndex(Iterable<FunctionSource> functions)
    : ordered = functions.toList(growable: false)
        ..sort((FunctionSource left, FunctionSource right) {
          final int path = left.path.compareTo(right.path);
          return path != 0 ? path : left.line.compareTo(right.line);
        }) {
    for (final FunctionSource function in ordered) {
      nameCounts.update(
        function.name,
        (int count) => count + 1,
        ifAbsent: () => 1,
      );
    }
    final Set<String> names = nameCounts.keys.toSet();
    for (final FunctionSource function in ordered) {
      final String code = _codeWithoutCommentsAndStrings(function.source);
      strippedSources.add(code);
      for (final RegExpMatch match in _identifier.allMatches(code)) {
        final String identifier = match.requiredGroup(1);
        if (names.contains(identifier)) {
          referenceCounts.update(
            identifier,
            (int count) => count + 1,
            ifAbsent: () => 1,
          );
        }
      }
      for (final RegExpMatch match in _call.allMatches(code)) {
        var cursor = match.start - 1;
        while (cursor >= 0 && code[cursor].trim().isEmpty) {
          cursor--;
        }
        if (cursor >= 0 && code[cursor] == '.') {
          final String receiver = code.substring(0, cursor).trimRight();
          if (!cachedRegExp(r'(?:this|self)$').hasMatch(receiver)) continue;
        }
        final int open = code.indexOf('(', match.start);
        final int close = _matchingDelimiter(code, open, '(', ')');
        if (close == -1) continue;
        final String rawArguments = code.substring(open + 1, close);
        final List<String> arguments = rawArguments.trim().isEmpty
            ? const <String>[]
            : _splitTopLevel(
                rawArguments,
              ).map((String value) => value.trim()).toList(growable: false);
        calls
            .putIfAbsent(
              match.requiredGroup(1),
              () => <({FunctionSource owner, List<String> arguments})>[],
            )
            .add((owner: function, arguments: arguments));
      }
    }
  }

  static final RegExp _identifier = cachedRegExp(r'\b([A-Za-z_$][\w$]*)\b');
  static final RegExp _call = cachedRegExp(r'\b([A-Za-z_$][\w$]*)\s*\(');

  /// Functions in stable report order.
  final List<FunctionSource> ordered;

  /// Number of declarations sharing each function name.
  final Map<String, int> nameCounts = <String, int>{};

  /// Function bodies with comments and strings masked.
  final List<String> strippedSources = <String>[];

  /// Visible identifier references grouped by function name.
  final Map<String, int> referenceCounts = <String, int>{};

  /// Calls grouped by callee name and owning function body.
  final Map<String, List<({FunctionSource owner, List<String> arguments})>>
  calls = <String, List<({FunctionSource owner, List<String> arguments})>>{};

  /// Calls to [target] outside its own function body.
  List<List<String>> visibleCalls(FunctionSource target) => <List<String>>[
    for (final ({FunctionSource owner, List<String> arguments}) call
        in calls[target.name] ??
            const <({FunctionSource owner, List<String> arguments})>[])
      if (!identical(call.owner, target)) call.arguments,
  ];

  /// Total visible lexical references to [identifier].
  int referenceCount(String identifier) => referenceCounts[identifier] ?? 0;
}

/// Computed control-flow metrics for a function-like block.
final class FunctionMetrics {
  /// Creates computed metrics.
  const FunctionMetrics({
    required this.function,
    required this.cyclomatic,
    required this.cognitive,
    required this.length,
  });

  /// Source metadata.
  final FunctionSource function;

  /// Cyclomatic complexity.
  final int cyclomatic;

  /// Nesting-weighted cognitive complexity.
  final int cognitive;

  /// Source line count.
  final int length;
}

/// Generic repository complexity and layout heuristics.
final class RepositoryAnalysis {
  /// Creates repository analysis helpers.
  const RepositoryAnalysis();

  /// Computes control-flow metrics from adapter-provided function source.
  FunctionMetrics measure(FunctionSource function) {
    var cyclomatic = 1;
    var cognitive = 0;
    var depth = 0;
    var inBlockComment = false;
    ({String delimiter, bool raw})? multilineString;
    final bool supportsDartMultilineStrings = function.path.endsWith('.dart');
    for (final String rawLine in function.source.split('\n')) {
      final (
        source: String stringStripped,
        endsInMultilineString: ({String delimiter, bool raw})? nextString,
      ) = _stripDartAwareStringLiterals(
        rawLine,
        inBlockComment: inBlockComment,
        multilineString: multilineString,
        supportsDartMultilineStrings: supportsDartMultilineStrings,
      );
      multilineString = nextString;
      final (source: String code, endsInBlockComment: bool endsInBlockComment) =
          _stripComments(stringStripped, inBlockComment: inBlockComment);
      inBlockComment = endsInBlockComment;
      final int cyclomaticSignals = cachedRegExp(
        r'(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|case|catch)([^A-Za-z0-9_]|$)|&&|\|\|',
      ).allMatches(code).length;
      final int cognitiveSignals = cachedRegExp(
        r'(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|switch|catch)([^A-Za-z0-9_]|$)|&&|\|\|',
      ).allMatches(code).length;
      // A switch contributes one cognitive structural break, while its cases
      // contribute the alternative paths counted by cyclomatic complexity.
      // Counting both switch and case in both metrics overstates flat dispatch.
      cyclomatic += cyclomaticSignals;
      // Adapter function bodies include their own outer braces. That lexical
      // wrapper is not control-flow nesting and must not inflate every signal.
      cognitive += cognitiveSignals * (1 + math.max(0, depth - 1));
      depth += '{'.allMatches(code).length - '}'.allMatches(code).length;
      if (depth < 0) {
        depth = 0;
      }
    }
    return FunctionMetrics(
      function: function,
      cyclomatic: cyclomatic,
      cognitive: cognitive,
      length: function.source.split('\n').length,
    );
  }

  /// Emits complexity and optional function-length findings.
  List<Finding> complexityFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
  }) {
    final List<Finding> result = <Finding>[];
    for (final FunctionSource function in functions) {
      final FunctionMetrics metrics = measure(function);
      if (metrics.cyclomatic > config.complexityThreshold ||
          metrics.cognitive > config.cognitiveThreshold) {
        result.add(
          Finding(
            code: 'complex-function',
            severity: RuleSeverity.warn,
            path: function.path,
            line: function.line,
            endLine: function.line,
            message:
                '${function.name} complexity=${metrics.cyclomatic} cognitive=${metrics.cognitive}',
          ),
        );
      }
      if (config.maxFunctionLines > 0 &&
          metrics.length > config.maxFunctionLines) {
        result.add(
          Finding(
            code: 'long-function',
            severity: RuleSeverity.warn,
            path: function.path,
            line: function.line,
            endLine: function.line + metrics.length - 1,
            message:
                '${function.name} has ${metrics.length} lines (threshold ${config.maxFunctionLines})',
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(result);
  }

  /// Reports maximal chains of private, single-use functions that only forward
  /// unchanged arguments to another function in the same source file.
  List<Finding> trivialWrapperFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
  }) {
    final List<FunctionSource> ordered = functions.toList(growable: false)
      ..sort((FunctionSource left, FunctionSource right) {
        final int path = left.path.compareTo(right.path);
        return path != 0 ? path : left.line.compareTo(right.line);
      });
    final Map<FunctionSource, _TrivialForwarder> parsed =
        <FunctionSource, _TrivialForwarder>{};
    for (final FunctionSource function in ordered) {
      final _TrivialForwarder? forwarder = _trivialForwarder(function);
      if (forwarder != null) parsed[function] = forwarder;
    }

    final Map<FunctionSource, _TrivialForwarder> eligible =
        <FunctionSource, _TrivialForwarder>{};
    for (final MapEntry<FunctionSource, _TrivialForwarder> entry
        in parsed.entries) {
      final FunctionSource wrapper = entry.key;
      final _TrivialForwarder forwarder = entry.value;
      final int targetMatches = ordered
          .where(
            (FunctionSource function) =>
                function.path == wrapper.path &&
                function.name == forwarder.target &&
                function != wrapper,
          )
          .length;
      if (targetMatches != 1) continue;

      final int callers = ordered
          .where(
            (FunctionSource function) =>
                function.path == wrapper.path && function != wrapper,
          )
          .where(
            (FunctionSource function) =>
                _callsFunction(function.source, wrapper.name),
          )
          .length;
      if (callers == 1) eligible[wrapper] = forwarder;
    }

    FunctionSource? nextWrapper(FunctionSource wrapper) {
      final String target = eligible.requiredValue(wrapper).target;
      final List<FunctionSource> matches = eligible.keys
          .where(
            (FunctionSource function) =>
                function.path == wrapper.path && function.name == target,
          )
          .toList(growable: false);
      return matches.length == 1 ? matches.single : null;
    }

    final Set<FunctionSource> nested = <FunctionSource>{};
    for (final FunctionSource wrapper in eligible.keys) {
      final FunctionSource? next = nextWrapper(wrapper);
      if (next != null) nested.add(next);
    }

    final List<Finding> findings = <Finding>[];
    final Set<FunctionSource> reported = <FunctionSource>{};
    void reportChain(FunctionSource outermost) {
      final List<FunctionSource> wrappers = <FunctionSource>[];
      FunctionSource current = outermost;
      while (reported.add(current)) {
        wrappers.add(current);
        final FunctionSource? next = nextWrapper(current);
        if (next == null || reported.contains(next)) break;
        current = next;
      }
      final String terminal = eligible.requiredValue(wrappers.last).target;
      final List<String> path = <String>[
        ...wrappers.map((FunctionSource wrapper) => wrapper.name),
        terminal,
      ];
      final bool isChain = wrappers.length > 1;
      findings.add(
        Finding(
          code: 'single-use-trivial-wrapper',
          severity:
              config.severityOverrides['single-use-trivial-wrapper'] ??
              RuleSeverity.info,
          path: outermost.path,
          line: outermost.line,
          endLine: outermost.endLine,
          message: isChain
              ? '${wrappers.length} single-use forwarding wrappers form the chain `${path.join('` -> `')}`'
              : '`${outermost.name}` has one caller and only forwards unchanged arguments to `$terminal`',
          confidence: 'high',
          why: isChain
              ? 'A chain of single-use forwarding functions adds repeated navigation without owning policy, transformation, validation, or resource lifetime.'
              : 'A single-use forwarding function adds navigation without owning policy, transformation, validation, or resource lifetime.',
          suggestion: isChain
              ? 'Collapse the chain into its caller unless a wrapper is an intentional extension or compatibility boundary.'
              : 'Inline the wrapper unless it is an intentional extension or compatibility boundary.',
        ),
      );
    }

    for (final FunctionSource wrapper in eligible.keys) {
      if (!nested.contains(wrapper)) reportChain(wrapper);
    }
    for (final FunctionSource wrapper in eligible.keys) {
      if (!reported.contains(wrapper)) reportChain(wrapper);
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Reports private one-caller factories that only construct one product.
  List<Finding> singleProductFactoryFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
  }) {
    final List<FunctionSource> ordered = functions.toList(growable: false)
      ..sort((FunctionSource left, FunctionSource right) {
        final int path = left.path.compareTo(right.path);
        return path != 0 ? path : left.line.compareTo(right.line);
      });
    final Map<String, int> nameCounts = <String, int>{};
    for (final FunctionSource function in ordered) {
      nameCounts.update(
        function.name,
        (int count) => count + 1,
        ifAbsent: () => 1,
      );
    }

    final List<Finding> findings = <Finding>[];
    for (final FunctionSource function in ordered) {
      if (!_supportsLanguage(function.path, _singleProductFactoryLanguages) ||
          !_isPrivateFunction(function) ||
          nameCounts[function.name] != 1 ||
          _isOverride(function.source)) {
        continue;
      }
      final String? product = _singleProductFactory(function);
      if (product == null) continue;
      final List<List<String>> calls = ordered
          .where((FunctionSource caller) => caller != function)
          .expand(
            (FunctionSource caller) =>
                _callArguments(caller.source, function.name),
          )
          .toList(growable: false);
      if (calls.length != 1) continue;
      final int references = ordered.fold(
        0,
        (int total, FunctionSource current) =>
            total +
            _identifierCount(
              _codeWithoutCommentsAndStrings(current.source),
              function.name,
            ),
      );
      if (references != 2) continue;

      findings.add(
        Finding(
          code: 'single-product-factory',
          severity:
              config.severityOverrides['single-product-factory'] ??
              RuleSeverity.info,
          path: function.path,
          line: function.line,
          endLine: function.endLine,
          message:
              '`${function.name}` has one caller and only constructs `$product` with unchanged arguments',
          confidence: 'high',
          why:
              'A one-caller factory with one fixed product and no owned policy, lifecycle, or transformation adds indirection without current variation.',
          suggestion:
              'Construct the product at the caller until selection, lifecycle, or shared creation policy is needed.',
        ),
      );
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Reports private function parameters whose visible callers always pass the
  /// same simple constant.
  List<Finding> constantArgumentFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
    YagniCallIndex? callIndex,
  }) {
    final YagniCallIndex index = callIndex ?? YagniCallIndex(functions);
    final List<Finding> findings = <Finding>[];
    for (final FunctionSource function in index.ordered) {
      if (!_supportsLanguage(function.path, _constantArgumentLanguages) ||
          !_isPrivateFunction(function) ||
          index.nameCounts[function.name] != 1 ||
          _isOverride(function.source)) {
        continue;
      }
      final List<String>? parameters = _requiredParameterNames(function);
      if (parameters == null || parameters.isEmpty) continue;
      final List<List<String>> calls = index.visibleCalls(function);
      if (calls.length < 3 ||
          calls.any(
            (List<String> arguments) => arguments.length != parameters.length,
          )) {
        continue;
      }
      final int references = index.referenceCount(function.name);
      if (references != calls.length + 1) continue;

      final String functionCode = _codeWithoutCommentsAndStrings(
        function.source,
      );
      for (var index = 0; index < parameters.length; index++) {
        final String parameter = parameters[index];
        if (_identifierCount(functionCode, parameter) < 2) continue;
        final String? constant = _simpleConstant(calls.first[index]);
        if (constant == null ||
            calls
                .skip(1)
                .any(
                  (List<String> arguments) =>
                      _simpleConstant(arguments[index]) != constant,
                )) {
          continue;
        }
        findings.add(
          Finding(
            code: 'constant-argument-parameter',
            severity:
                config.severityOverrides['constant-argument-parameter'] ??
                RuleSeverity.info,
            path: function.path,
            line: function.line,
            endLine: function.endLine,
            message:
                '`${function.name}` receives the constant `$constant` for parameter `$parameter` at all ${calls.length} visible call sites',
            confidence: 'high',
            why:
                'A parameter whose callers always supply one value advertises flexibility that the current code does not use.',
            suggestion:
                'Move the constant into the private function and remove the parameter until callers need real variation.',
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Reports optional private callback hooks that visible callers never use.
  List<Finding> unusedCustomizationHookFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
    YagniCallIndex? callIndex,
  }) {
    final YagniCallIndex index = callIndex ?? YagniCallIndex(functions);
    final List<Finding> findings = <Finding>[];
    for (final FunctionSource function in index.ordered) {
      if (!_supportsLanguage(function.path, _customizationHookLanguages) ||
          !_isPrivateFunction(function) ||
          index.nameCounts[function.name] != 1 ||
          _isOverride(function.source)) {
        continue;
      }
      final List<_OptionalParameter> hooks = _optionalParameters(function)
          .where((_OptionalParameter parameter) {
            return parameter.callbackLike && parameter.invoked;
          })
          .toList(growable: false);
      if (hooks.isEmpty) continue;
      final List<List<String>> calls = index.visibleCalls(function);
      if (calls.length < 3) continue;
      final int references = index.referenceCount(function.name);
      if (references != calls.length + 1) continue;

      for (final _OptionalParameter hook in hooks) {
        if (calls.any((List<String> arguments) => hook.isSupplied(arguments))) {
          continue;
        }
        findings.add(
          Finding(
            code: 'unused-customization-hook',
            severity:
                config.severityOverrides['unused-customization-hook'] ??
                RuleSeverity.info,
            path: function.path,
            line: function.line,
            endLine: function.endLine,
            message:
                '`${function.name}` exposes optional customization hook `${hook.name}`, but none of its ${calls.length} visible callers supplies it',
            confidence: 'high',
            why:
                'An unused callback hook adds branching and API surface for variation that has no current caller.',
            suggestion:
                'Remove the hook and its fallback path until a concrete caller needs customization.',
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Reports optional private parameters that visible callers always omit.
  List<Finding> unusedOptionalParameterFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
    YagniCallIndex? callIndex,
  }) {
    final YagniCallIndex index = callIndex ?? YagniCallIndex(functions);
    final List<Finding> findings = <Finding>[];
    for (final FunctionSource function in index.ordered) {
      if (!_supportsLanguage(function.path, _optionalParameterLanguages) ||
          !_isPrivateFunction(function) ||
          index.nameCounts[function.name] != 1 ||
          _isOverride(function.source)) {
        continue;
      }
      final List<_OptionalParameter> parameters = _optionalParameters(function)
          .where((_OptionalParameter parameter) {
            return !parameter.callbackLike || !parameter.invoked;
          })
          .toList(growable: false);
      if (parameters.isEmpty) continue;
      final List<List<String>> calls = index.visibleCalls(function);
      if (calls.length < 3) continue;
      final int references = index.referenceCount(function.name);
      if (references != calls.length + 1) continue;

      for (final _OptionalParameter parameter in parameters) {
        if (calls.any(parameter.isSupplied)) continue;
        findings.add(
          Finding(
            code: 'unused-optional-parameter',
            severity:
                config.severityOverrides['unused-optional-parameter'] ??
                RuleSeverity.info,
            path: function.path,
            line: function.line,
            endLine: function.endLine,
            message:
                '`${function.name}` exposes optional parameter `${parameter.name}`, but none of its ${calls.length} visible callers supplies it',
            confidence: 'high',
            why:
                'An optional parameter that every caller omits adds API surface and a dormant behavior path without current variation.',
            suggestion:
                'Use the default behavior directly and remove the parameter until a concrete caller needs variation.',
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Reports configuration keys supplied by every visible caller but never
  /// read by the private function receiving the configuration object.
  List<Finding> unusedConfigurationOptionFindings({
    required Iterable<FunctionSource> functions,
    required AnalysisConfig config,
    YagniCallIndex? callIndex,
  }) {
    final YagniCallIndex index = callIndex ?? YagniCallIndex(functions);
    final List<Finding> findings = <Finding>[];
    for (final FunctionSource function in index.ordered) {
      if (!_supportsLanguage(function.path, _configurationOptionLanguages) ||
          !_isPrivateFunction(function) ||
          index.nameCounts[function.name] != 1 ||
          _isOverride(function.source)) {
        continue;
      }
      final List<String>? parameters = _requiredParameterNames(function);
      if (parameters == null || parameters.isEmpty) continue;
      final List<List<String>> calls = index.visibleCalls(function);
      if (calls.length < 3 ||
          calls.any(
            (List<String> arguments) => arguments.length != parameters.length,
          )) {
        continue;
      }
      final int references = index.referenceCount(function.name);
      if (references != calls.length + 1) continue;

      final String body = _functionBodyCode(function);
      for (var index = 0; index < parameters.length; index++) {
        final String parameter = parameters[index];
        if (!_configurationParameterName.hasMatch(parameter)) continue;
        final Set<String>? firstKeys = _configurationKeys(calls.first[index]);
        if (firstKeys == null || firstKeys.isEmpty) continue;
        final Set<String> commonKeys = Set<String>.of(firstKeys);
        var complete = true;
        for (final List<String> call in calls.skip(1)) {
          final Set<String>? keys = _configurationKeys(call[index]);
          if (keys == null) {
            complete = false;
            break;
          }
          commonKeys.retainAll(keys);
        }
        if (!complete || commonKeys.isEmpty) continue;

        final RegExp access = cachedRegExp(
          '\\b${RegExp.escape(parameter)}\\s*(?:(?:\\?|!)\\s*)?\\.\\s*([A-Za-z_\$][\\w\$]*)',
        );
        final List<RegExpMatch> accesses = access
            .allMatches(body)
            .toList(growable: false);
        if (_identifierCount(body, parameter) != accesses.length) continue;
        final Set<String> readKeys = accesses
            .map((RegExpMatch match) => match.requiredGroup(1))
            .toSet();
        final List<String> unused = commonKeys.difference(readKeys).toList()
          ..sort();
        for (final String option in unused) {
          findings.add(
            Finding(
              code: 'unused-configuration-option',
              severity:
                  config.severityOverrides['unused-configuration-option'] ??
                  RuleSeverity.info,
              path: function.path,
              line: function.line,
              endLine: function.endLine,
              message:
                  '`${function.name}` receives configuration option `$option` from all ${calls.length} visible callers but never reads it',
              confidence: 'high',
              why:
                  'A configuration option that every caller supplies but the implementation never reads adds misleading variation and maintenance cost.',
              suggestion:
                  'Remove the option from callers and its configuration type until the implementation needs it.',
            ),
          );
        }
      }
    }
    return List<Finding>.unmodifiable(findings);
  }

  /// Emits file-size and unstructured-control-flow findings.
  List<Finding> fileFindings({
    required Map<String, String> sources,
    required AnalysisConfig config,
  }) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = entry.value.split('\n');
      if (config.maxFileLines > 0 && lines.length > config.maxFileLines) {
        result.add(
          Finding(
            code: 'large-file',
            severity: RuleSeverity.warn,
            path: entry.key,
            line: 1,
            endLine: 1,
            message: '${lines.length} lines > ${config.maxFileLines}',
            confidence: 'high',
            suggestion:
                'Split the file along cohesive module responsibilities.',
          ),
        );
      }
      final bool supportsGoto = cachedRegExp(
        r'\.(?:c|cs|h)$',
        caseSensitive: false,
      ).hasMatch(entry.key);
      final List<int> gotoLines = <int>[];
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String source, bool endsInBlockComment}) commentStripped =
            _stripComments(
              _stripStringLiterals(lines[index]),
              inBlockComment: inBlockComment,
            );
        inBlockComment = commentStripped.endsInBlockComment;
        final String line = commentStripped.source.trim();
        if (supportsGoto &&
            cachedRegExp(r'^goto\s+[A-Za-z_]\w*\s*;').hasMatch(line)) {
          gotoLines.add(index + 1);
        }
      }
      if (gotoLines.isNotEmpty) {
        result.add(
          Finding(
            code: 'goto-statement',
            severity: RuleSeverity.warn,
            path: entry.key,
            line: gotoLines.first,
            endLine: gotoLines.first,
            message: gotoLines.length == 1
                ? 'use of goto makes control flow hard to review and analyze'
                : '${gotoLines.length} goto statements make control flow hard to review and analyze',
            confidence: 'high',
            suggestion:
                'Use structured control flow, extraction, or early returns.',
            relatedFiles: gotoLines
                .skip(1)
                .map((int line) => '${entry.key}:$line')
                .toList(growable: false),
          ),
        );
      }
    }
    return result;
  }

  /// Emits configurable source-layout policy findings.
  List<Finding> structureFindings({
    required Iterable<SourceFile> files,
    required AnalysisConfig config,
  }) {
    final bool enabled =
        config.structureMaxTopLevelFiles >= 0 ||
        config.structureAllowedTopLevel.isNotEmpty ||
        config.structureRequiredDirectories.isNotEmpty;
    if (!enabled) {
      return const <Finding>[];
    }
    final List<Finding> result = <Finding>[];
    final List<String> roots = config.structureSourceRoots.isEmpty
        ? const <String>['src']
        : config.structureSourceRoots;
    final List<SourceFile> sourceFiles = files.toList(growable: false);
    for (final String root in roots) {
      final String normalizedRoot = root
          .replaceAll('\\', '/')
          .replaceAll(cachedRegExp(r'^/+|/+$'), '');
      final Directory rootDirectory = Directory(
        path.join(config.root, normalizedRoot),
      );
      if (!rootDirectory.existsSync()) {
        if (config.structureRequiredDirectories.isNotEmpty) {
          result.add(
            Finding(
              code: 'structure-missing-source-root',
              severity: RuleSeverity.warn,
              path: normalizedRoot,
              line: 1,
              message: 'configured source root is missing: $normalizedRoot',
              suggestion:
                  'Create the source root or remove it from [structure].source_roots.',
            ),
          );
        }
        continue;
      }
      for (final String required in config.structureRequiredDirectories) {
        final String requiredPath = '$normalizedRoot/$required'.replaceAll(
          '//',
          '/',
        );
        if (!Directory(path.join(config.root, requiredPath)).existsSync()) {
          result.add(
            Finding(
              code: 'structure-missing-required-dir',
              severity: RuleSeverity.warn,
              path: requiredPath,
              line: 1,
              message: 'required source subdirectory is missing: $requiredPath',
              suggestion:
                  'Create the subsystem folder or update [structure].required_dirs.',
            ),
          );
        }
      }
      final List<String> topLevel =
          sourceFiles
              .map((SourceFile file) => file.relativePath)
              .where(
                (String relative) => relative.startsWith('$normalizedRoot/'),
              )
              .where(
                (String relative) =>
                    relative
                        .substring(normalizedRoot.length + 1)
                        .contains('/') ==
                    false,
              )
              .where(
                (String relative) => !_allowedTopLevel(
                  relative,
                  normalizedRoot,
                  config.structureAllowedTopLevel,
                ),
              )
              .toList()
            ..sort();
      if (config.structureMaxTopLevelFiles >= 0 &&
          topLevel.length > config.structureMaxTopLevelFiles) {
        result.add(
          Finding(
            code: 'structure-top-level-file',
            severity: RuleSeverity.warn,
            path: normalizedRoot,
            line: 1,
            message:
                'source root has ${topLevel.length} top-level file(s), allowed ${config.structureMaxTopLevelFiles}',
            suggestion:
                'Move implementation files into subsystem folders or add intentional entry/facade files to [structure].allowed_top_level.',
            relatedFiles: topLevel,
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(result);
  }

  static bool _allowedTopLevel(
    String relative,
    String root,
    List<String> allowed,
  ) {
    final String name = relative.substring(root.length + 1);
    return allowed.any((String item) => item == name || item == relative);
  }
}

/// Groups several independent YAGNI findings in one file into holistic guidance.
final class YagniConcentrationAnalysis {
  /// Creates the deterministic file-level concentration analysis.
  const YagniConcentrationAnalysis();

  /// Reports files with at least three YAGNI findings from two distinct rules.
  List<Finding> findings({
    required Iterable<Finding> findings,
    required Set<String> activeYagniRuleIds,
    required AnalysisConfig config,
  }) {
    final Map<String, List<Finding>> byPath = <String, List<Finding>>{};
    for (final Finding finding in findings) {
      if (finding.path.isEmpty ||
          finding.code == 'yagni-concentration' ||
          !activeYagniRuleIds.contains(finding.code)) {
        continue;
      }
      byPath.putIfAbsent(finding.path, () => <Finding>[]).add(finding);
    }

    final List<Finding> result = <Finding>[];
    final List<String> paths = byPath.keys.toList()..sort();
    for (final String path in paths) {
      final List<Finding> fileFindings = byPath.requiredValue(path)
        ..sort((Finding left, Finding right) {
          final int line = left.line.compareTo(right.line);
          return line != 0 ? line : left.code.compareTo(right.code);
        });
      final List<String> ruleIds =
          fileFindings.map((Finding finding) => finding.code).toSet().toList()
            ..sort();
      if (fileFindings.length < 3 || ruleIds.length < 2) continue;

      result.add(
        Finding(
          code: 'yagni-concentration',
          severity:
              config.severityOverrides['yagni-concentration'] ??
              RuleSeverity.info,
          path: path,
          line: fileFindings.first.line,
          message:
              '${fileFindings.length} YAGNI findings from ${ruleIds.length} rule families are concentrated in this file: ${ruleIds.join(', ')}',
          confidence: 'medium',
          why:
              'Several independent signs of unused flexibility or one-use indirection in one file suggest the design should be reviewed as a whole instead of fixing each symptom separately.',
          suggestion:
              'Start from the actual callers and required behavior, then remove unused variation and collapse one-use layers together; retain boundaries that own policy, validation, lifecycle, or an external contract.',
        ),
      );
    }
    return List<Finding>.unmodifiable(result);
  }
}

/// Heuristics that identify feature flag references in source text.
final class FeatureFlagAnalysis {
  /// Finds unique flag references in every source file.
  List<Finding> findings(Map<String, String> sources) {
    final RegExp pattern = cachedRegExp(
      r'(^|[^A-Za-z0-9_.])(flags|Flags|Config)(?:\.|::)([A-Za-z_]\w*)',
      multiLine: true,
    );
    const Set<String> ignored = <String>{
      'trygetvalue',
      'getvalue',
      'getvalueordefault',
      'contains',
      'containskey',
      'add',
      'remove',
      'clear',
      'count',
      'push',
      'pop',
      'join',
      'map',
      'filter',
      'length',
      'get',
      'set',
      'hasflag',
      'setflag',
      'html',
      'foo',
      'bar',
      'baz',
      'test',
      'mock',
      'put',
    };
    final List<Finding> result = <Finding>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String sourcePath in paths) {
      final Set<String> seen = <String>{};
      final List<String> lines = sources.requiredValue(sourcePath).split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String line = _stripStringLiterals(lines[index]);
        for (final RegExpMatch match in pattern.allMatches(line)) {
          final String receiver = match.requiredGroup(2);
          final String flag = match.requiredGroup(3);
          final bool hasFeatureSemantics = cachedRegExp(
            r'feature|experiment|rollout|beta|treatment|variant',
            caseSensitive: false,
          ).hasMatch(flag);
          final bool genericMember =
              receiver == 'Config' ||
              receiver == 'flags' ||
              receiver == 'Flags';
          if ((genericMember && !hasFeatureSemantics) ||
              ignored.contains(flag.toLowerCase()) ||
              !seen.add(flag)) {
            continue;
          }
          result.add(
            Finding(
              code: 'feature-flag',
              severity: RuleSeverity.warn,
              path: sourcePath,
              line: index + 1,
              endLine: index + 1,
              message: 'feature flag reference: $flag',
            ),
          );
        }
      }
    }
    return List<Finding>.unmodifiable(result);
  }
}

/// Adapter-provided generic declaration for YAGNI analysis.
final class GenericDeclaration {
  /// Creates a generic declaration.
  const GenericDeclaration({
    required this.path,
    required this.name,
    required this.line,
    required this.endLine,
    required this.parameters,
    required this.declaration,
    required this.usageSource,
  });

  /// Project-relative source path.
  final String path;

  /// Declaration name.
  final String name;

  /// One-based declaration line.
  final int line;

  /// One-based declaration end line.
  final int endLine;

  /// Generic parameter names.
  final List<String> parameters;

  /// Declaration text for reporting.
  final String declaration;

  /// Signature and body text excluding generic parameter declaration.
  final String usageSource;
}

/// Reports generic parameters that have no visible current use.
final class YagniAnalysis {
  /// Finds unused generic parameters in adapter-provided declarations.
  List<Finding> unusedGenericParameters(
    Iterable<GenericDeclaration> declarations,
  ) {
    final List<Finding> result = <Finding>[];
    for (final GenericDeclaration declaration in declarations) {
      for (final String parameter in declaration.parameters) {
        if (cachedRegExp(
          '\\b${RegExp.escape(parameter)}\\b',
        ).hasMatch(declaration.usageSource)) {
          continue;
        }
        result.add(
          Finding(
            code: 'unused-generic-parameter',
            severity: RuleSeverity.warn,
            path: declaration.path,
            line: declaration.line,
            endLine: declaration.endLine,
            message:
                "generic parameter '$parameter' is not used by ${declaration.name}",
            confidence: 'high',
            why:
                'An unused type parameter advertises flexibility without affecting behavior.',
            suggestion:
                'Remove the parameter unless it expresses a current documented constraint.',
            snippet: declaration.declaration,
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(result);
  }
}

/// Churn and commit-frequency data for a discovered source file.
final class Hotspot {
  /// Creates a computed Git history hotspot.
  const Hotspot({
    required this.path,
    required this.commits,
    required this.added,
    required this.deleted,
  });

  /// Project-relative source path.
  final String path;

  /// Number of commits that touched the path.
  final int commits;

  /// Cumulative added lines.
  final int added;

  /// Cumulative deleted lines.
  final int deleted;

  /// Total line churn.
  int get churn => added + deleted;

  /// Churn weighted by commit frequency.
  double get risk => churn * (1 + math.log(1 + commits));
}

/// Parses Git numstat history and ranks discovered files by change risk.
final class HotspotAnalysis {
  /// Parses output from `git log --numstat --format=format:__CODE_BUSTER_COMMIT__`.
  static List<Hotspot> parseNumstat(
    String text, {
    Set<String> allowed = const <String>{},
  }) {
    final Map<String, _HotspotTotals> totals = <String, _HotspotTotals>{};
    final Set<String> touched = <String>{};
    void finishCommit() {
      for (final String sourcePath in touched) {
        totals.putIfAbsent(sourcePath, _HotspotTotals.new).commits++;
      }
      touched.clear();
    }

    for (final String line in text.split('\n')) {
      if (line.trim() == '__CODE_BUSTER_COMMIT__') {
        finishCommit();
        continue;
      }
      final List<String> fields = line.split('\t');
      if (fields.length < 3 || fields[0] == '-' || fields[1] == '-') {
        continue;
      }
      final String sourcePath = fields[2].replaceAll('\\', '/');
      if (allowed.isNotEmpty && !allowed.contains(sourcePath)) {
        continue;
      }
      final int? added = int.tryParse(fields[0]);
      final int? deleted = int.tryParse(fields[1]);
      if (added == null || deleted == null) {
        continue;
      }
      final _HotspotTotals total = totals.putIfAbsent(
        sourcePath,
        _HotspotTotals.new,
      );
      total.added += added;
      total.deleted += deleted;
      touched.add(sourcePath);
    }
    finishCommit();
    final List<Hotspot> result =
        totals.entries
            .map(
              (MapEntry<String, _HotspotTotals> entry) => Hotspot(
                path: entry.key,
                commits: entry.value.commits,
                added: entry.value.added,
                deleted: entry.value.deleted,
              ),
            )
            .toList()
          ..sort((Hotspot left, Hotspot right) {
            final int risk = right.risk.compareTo(left.risk);
            return risk == 0 ? left.path.compareTo(right.path) : risk;
          });
    return List<Hotspot>.unmodifiable(result);
  }

  /// Collects churn data from local Git history for [allowed] discovered paths.
  static List<Hotspot> fromGit({
    required String root,
    required Set<String> allowed,
  }) {
    final ProcessResult result = Process.runSync(
      'git',
      <String>[
        '-C',
        root,
        'log',
        '--no-merges',
        '--numstat',
        '--format=format:__CODE_BUSTER_COMMIT__',
      ],
      stdoutEncoding: const SystemEncoding(),
      stderrEncoding: const SystemEncoding(),
    );
    if (result.exitCode != 0) {
      return const <Hotspot>[];
    }
    return parseNumstat(result.stdout as String, allowed: allowed);
  }
}

final class _HotspotTotals {
  int commits = 0;
  int added = 0;
  int deleted = 0;
}

({String source, bool endsInBlockComment}) _stripComments(
  String line, {
  required bool inBlockComment,
}) {
  final StringBuffer result = StringBuffer();
  var cursor = 0;
  while (cursor < line.length) {
    if (inBlockComment) {
      final int commentEnd = line.indexOf('*/', cursor);
      if (commentEnd == -1) {
        return (source: result.toString(), endsInBlockComment: true);
      }
      inBlockComment = false;
      cursor = commentEnd + 2;
      continue;
    }

    final int lineComment = line.indexOf('//', cursor);
    final int blockComment = line.indexOf('/*', cursor);
    if (lineComment != -1 &&
        (blockComment == -1 || lineComment < blockComment)) {
      result.write(line.substring(cursor, lineComment));
      break;
    }
    if (blockComment == -1) {
      result.write(line.substring(cursor));
      break;
    }
    result.write(line.substring(cursor, blockComment));
    inBlockComment = true;
    cursor = blockComment + 2;
  }
  return (source: result.toString(), endsInBlockComment: inBlockComment);
}

String _stripStringLiterals(String source) => source.replaceAll(
  cachedRegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' '''.trim()),
  ' ',
);

typedef _DartMultilineStringState = ({String delimiter, bool raw});
typedef _StringMaskResult = ({
  String source,
  _DartMultilineStringState? endsInMultilineString,
});

_StringMaskResult _stripDartAwareStringLiterals(
  String source, {
  required _DartMultilineStringState? multilineString,
  required bool supportsDartMultilineStrings,
  required bool inBlockComment,
}) {
  if (!supportsDartMultilineStrings) {
    return (source: _stripStringLiterals(source), endsInMultilineString: null);
  }

  final StringBuffer result = StringBuffer();
  var cursor = 0;
  var scanningBlockComment = inBlockComment;
  while (cursor < source.length) {
    final _DartMultilineStringState? activeString = multilineString;
    if (activeString != null) {
      final int close = _dartMultilineStringClose(source, cursor, activeString);
      if (close == -1) {
        result.write(''.padRight(source.length - cursor));
        return (
          source: result.toString(),
          endsInMultilineString: multilineString,
        );
      }
      final int afterClose = close + activeString.delimiter.length;
      result.write(''.padRight(afterClose - cursor));
      cursor = afterClose;
      multilineString = null;
      continue;
    }
    if (scanningBlockComment) {
      final int commentEnd = source.indexOf('*/', cursor);
      if (commentEnd == -1) {
        result.write(source.substring(cursor));
        break;
      }
      final int afterComment = commentEnd + 2;
      result.write(source.substring(cursor, afterComment));
      cursor = afterComment;
      scanningBlockComment = false;
      continue;
    }
    if (source.startsWith('//', cursor)) {
      result.write(source.substring(cursor));
      break;
    }
    if (source.startsWith('/*', cursor)) {
      result.write('/*');
      cursor += 2;
      scanningBlockComment = true;
      continue;
    }

    final String character = source[cursor];
    if (character != "'" && character != '"') {
      result.write(character);
      cursor++;
      continue;
    }

    final bool raw =
        cursor > 0 &&
        (source[cursor - 1] == 'r' || source[cursor - 1] == 'R') &&
        (cursor == 1 ||
            !cachedRegExp(r'[A-Za-z0-9_]').hasMatch(source[cursor - 2]));
    final String delimiter = character + character + character;
    if (source.startsWith(delimiter, cursor)) {
      final _DartMultilineStringState state = (delimiter: delimiter, raw: raw);
      final int contentStart = cursor + delimiter.length;
      final int close = _dartMultilineStringClose(source, contentStart, state);
      if (close == -1) {
        result.write(''.padRight(source.length - cursor));
        return (source: result.toString(), endsInMultilineString: state);
      }
      final int afterClose = close + delimiter.length;
      result.write(''.padRight(afterClose - cursor));
      cursor = afterClose;
      continue;
    }

    final int start = cursor;
    cursor++;
    while (cursor < source.length) {
      if (source[cursor] == character &&
          (raw || !_isBackslashEscaped(source, cursor))) {
        cursor++;
        break;
      }
      cursor++;
    }
    result.write(''.padRight(cursor - start));
  }
  return (source: result.toString(), endsInMultilineString: multilineString);
}

int _dartMultilineStringClose(
  String source,
  int start,
  _DartMultilineStringState state,
) {
  var cursor = start;
  while (true) {
    final int close = source.indexOf(state.delimiter, cursor);
    if (close == -1) return -1;
    if (state.raw || !_isBackslashEscaped(source, close)) return close;
    cursor = close + 1;
  }
}

bool _isBackslashEscaped(String source, int index) {
  var backslashes = 0;
  for (
    var cursor = index - 1;
    cursor >= 0 && source[cursor] == '\\';
    cursor--
  ) {
    backslashes++;
  }
  return backslashes.isOdd;
}

final class _TrivialForwarder {
  const _TrivialForwarder(this.target);

  final String target;
}

_TrivialForwarder? _trivialForwarder(FunctionSource function) {
  final String source = function.source.trim();
  if (!_supportsLanguage(function.path, _trivialWrapperLanguages) ||
      !_isPrivateFunction(function) ||
      _isOverride(function.source)) {
    return null;
  }

  final RegExpMatch? declaration = cachedRegExp(
    '\\b${RegExp.escape(function.name)}\\s*\\(',
  ).firstMatch(source);
  if (declaration == null) return null;
  final int open = source.indexOf('(', declaration.start);
  final int close = _matchingDelimiter(source, open, '(', ')');
  if (close == -1) return null;
  final List<String>? parameters = _forwardedParameterNames(
    source.substring(open + 1, close),
    path: function.path,
  );
  if (parameters == null) return null;

  final RegExpMatch? call = _directForwardingCall(source.substring(close + 1));
  if (call == null) return null;
  final String target = call.requiredGroup(1);
  if (target == function.name) return null;
  final List<String> arguments = _splitTopLevel(call.requiredGroup(2))
      .map((String argument) => argument.trim())
      .where((String argument) => argument.isNotEmpty)
      .toList(growable: false);
  if (arguments.length != parameters.length) return null;
  for (var index = 0; index < parameters.length; index++) {
    if (arguments[index] != parameters[index]) return null;
  }
  return _TrivialForwarder(target);
}

String? _singleProductFactory(FunctionSource function) {
  final String source = function.source.trim();
  if (!cachedRegExp(
    r'^_?(?:(?:[Cc]reate|[Mm]ake|[Bb]uild|[Pp]rovide)(?:[A-Z_].*)?|.*Factory)$',
  ).hasMatch(function.name)) {
    return null;
  }
  final RegExpMatch? declaration = cachedRegExp(
    '\\b${RegExp.escape(function.name)}\\s*\\(',
  ).firstMatch(source);
  if (declaration == null) return null;
  final int open = source.indexOf('(', declaration.start);
  final int close = _matchingDelimiter(source, open, '(', ')');
  if (close == -1) return null;
  final List<String>? parameters = _forwardedParameterNames(
    source.substring(open + 1, close),
    path: function.path,
  );
  if (parameters == null) return null;
  final String? expression = _directReturnedExpression(
    source.substring(close + 1),
  );
  if (expression == null) return null;
  final RegExpMatch? construction = cachedRegExp(
    r'^(?:(?:new|const)\s+)?([A-Z][A-Za-z0-9_$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(([^()]*)\)$',
  ).firstMatch(expression);
  if (construction == null) return null;
  final List<String> arguments = _splitTopLevel(construction.requiredGroup(2))
      .map((String argument) => argument.trim())
      .where((String argument) => argument.isNotEmpty)
      .toList(growable: false);
  if (arguments.length != parameters.length) return null;
  for (var index = 0; index < parameters.length; index++) {
    if (arguments[index] != parameters[index]) return null;
  }
  return construction.requiredGroup(1);
}

const Set<String> _trivialWrapperLanguages = <String>{
  'cpp',
  'csharp',
  'dart',
  'go',
  'java',
  'javascript',
  'typescript',
  'python',
  'rust',
};

const Set<String> _singleProductFactoryLanguages = <String>{
  'cpp',
  'csharp',
  'dart',
  'java',
  'javascript',
  'typescript',
  'python',
};

const Set<String> _constantArgumentLanguages = _trivialWrapperLanguages;

const Set<String> _customizationHookLanguages = <String>{
  'csharp',
  'dart',
  'javascript',
  'typescript',
  'python',
};

const Set<String> _optionalParameterLanguages = _customizationHookLanguages;

const Set<String> _configurationOptionLanguages = <String>{
  'csharp',
  'dart',
  'javascript',
  'typescript',
  'python',
};

final RegExp _configurationParameterName = cachedRegExp(
  r'^(?:config|configuration|options|settings|preferences)$',
  caseSensitive: false,
);

bool _supportsLanguage(String path, Set<String> languages) {
  final String? language = _sourceLanguage(path);
  return language != null && languages.contains(language);
}

String? _sourceLanguage(String path) {
  final String lower = path.toLowerCase();
  if (lower.endsWith('.dart')) return 'dart';
  if (lower.endsWith('.py')) return 'python';
  if (lower.endsWith('.java')) return 'java';
  if (lower.endsWith('.cs')) return 'csharp';
  if (lower.endsWith('.go')) return 'go';
  if (lower.endsWith('.rs')) return 'rust';
  if (cachedRegExp(r'\.(?:ts|tsx|mts|cts)$').hasMatch(lower)) {
    return 'typescript';
  }
  if (cachedRegExp(r'\.(?:js|jsx|mjs|cjs)$').hasMatch(lower)) {
    return 'javascript';
  }
  if (cachedRegExp(r'\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$').hasMatch(lower)) {
    return 'cpp';
  }
  return null;
}

bool _isPrivateFunction(FunctionSource function) {
  final String? language = _sourceLanguage(function.path);
  final String source = function.source;
  if (function.name.startsWith('_')) return true;
  switch (language) {
    case 'cpp':
      return cachedRegExp(r'^\s*static\b').hasMatch(source);
    case 'csharp':
    case 'java':
      return cachedRegExp(r'\bprivate\b').hasMatch(source);
    case 'go':
      final String first = function.name.substring(0, 1);
      return first == first.toLowerCase();
    case 'rust':
      return !cachedRegExp(r'^\s*pub(?:\s|\()').hasMatch(source);
    case 'dart':
    case 'javascript':
    case 'typescript':
    case 'python':
    case null:
      return false;
  }
  return false;
}

bool _isOverride(String source) => cachedRegExp(
  r'@\s*override\b|\boverride\b',
  caseSensitive: false,
).hasMatch(source);

List<String>? _requiredParameterNames(FunctionSource function) {
  final String source = function.source;
  final RegExpMatch? declaration = cachedRegExp(
    '\\b${RegExp.escape(function.name)}\\s*\\(',
  ).firstMatch(source);
  if (declaration == null) return null;
  final int open = source.indexOf('(', declaration.start);
  final int close = _matchingDelimiter(source, open, '(', ')');
  if (close == -1) return null;
  final String parameters = source.substring(open + 1, close);
  if (parameters.contains('{') || parameters.contains('[')) return null;
  return _forwardedParameterNames(parameters, path: function.path);
}

String _functionBodyCode(FunctionSource function) {
  final String source = function.source;
  final RegExpMatch? declaration = cachedRegExp(
    '\\b${RegExp.escape(function.name)}\\s*\\(',
  ).firstMatch(source);
  if (declaration == null) return '';
  final int open = source.indexOf('(', declaration.start);
  final int close = _matchingDelimiter(source, open, '(', ')');
  if (close == -1) return '';
  return _codeWithoutCommentsAndStrings(source.substring(close + 1));
}

Set<String>? _configurationKeys(String argument) {
  var source = argument.trim();
  if (source.startsWith('{') && source.endsWith('}')) {
    source = source.substring(1, source.length - 1);
  } else {
    final RegExpMatch? constructor = cachedRegExp(
      r'^(?:(?:new|const)\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\((.*)\)$',
    ).firstMatch(source);
    if (constructor == null) return null;
    source = constructor.requiredGroup(1);
  }
  final Set<String> keys = <String>{};
  for (final String raw in _splitTopLevel(source)) {
    final String member = raw.trim();
    if (member.isEmpty) continue;
    final RegExpMatch? keyed = cachedRegExp(
      r'^([A-Za-z_$][\w$]*)\s*(?::|=)',
    ).firstMatch(member);
    if (keyed == null || !keys.add(keyed.requiredGroup(1))) return null;
  }
  return keys;
}

final class _OptionalParameter {
  const _OptionalParameter({
    required this.name,
    required this.positionalIndex,
    required this.named,
    required this.callbackLike,
    required this.invoked,
  });

  final String name;
  final int positionalIndex;
  final bool named;
  final bool callbackLike;
  final bool invoked;

  bool isSupplied(List<String> arguments) {
    if (arguments.any(
      (String argument) =>
          cachedRegExp('^${RegExp.escape(name)}\\s*(?::|=)').hasMatch(argument),
    )) {
      return true;
    }
    if (named) return false;
    final int positionalArguments = arguments
        .where(
          (String argument) =>
              !cachedRegExp(r'^[A-Za-z_$][\w$]*\s*(?::|=)').hasMatch(argument),
        )
        .length;
    return positionalArguments > positionalIndex;
  }
}

List<_OptionalParameter> _optionalParameters(FunctionSource function) {
  final String source = function.source;
  final RegExpMatch? declaration = cachedRegExp(
    '\\b${RegExp.escape(function.name)}\\s*\\(',
  ).firstMatch(source);
  if (declaration == null) return const <_OptionalParameter>[];
  final int open = source.indexOf('(', declaration.start);
  final int close = _matchingDelimiter(source, open, '(', ')');
  if (close == -1) return const <_OptionalParameter>[];
  final String body = _codeWithoutCommentsAndStrings(
    source.substring(close + 1),
  );

  final List<_OptionalParameter> parameters = <_OptionalParameter>[];
  var positionalIndex = 0;
  for (final String group in _splitTopLevel(
    source.substring(open + 1, close),
  )) {
    var parameterGroup = group.trim();
    var named = false;
    var groupOptional = false;
    if ((parameterGroup.startsWith('{') && parameterGroup.endsWith('}')) ||
        (parameterGroup.startsWith('[') && parameterGroup.endsWith(']'))) {
      named = parameterGroup.startsWith('{');
      groupOptional = true;
      parameterGroup = parameterGroup.substring(1, parameterGroup.length - 1);
    }
    for (final String raw in _splitTopLevel(parameterGroup)) {
      final String parameter = raw.trim();
      if (parameter.isEmpty) continue;
      final int equals = parameter.indexOf('=');
      final String declarationPart = equals == -1
          ? parameter
          : parameter.substring(0, equals).trim();
      final int colon = declarationPart.indexOf(':');
      final String nameSource = colon == -1
          ? declarationPart
          : declarationPart.substring(0, colon);
      final List<RegExpMatch> identifiers = cachedRegExp(
        r'[A-Za-z_$][\w$]*',
      ).allMatches(nameSource).toList(growable: false);
      if (identifiers.isEmpty) continue;
      final String name = identifiers.last.group(0)!;
      if (name == 'this' || name == 'self') continue;
      final bool optional =
          groupOptional ||
          equals != -1 ||
          cachedRegExp(
            '\\b${RegExp.escape(name)}\\s*\\?',
          ).hasMatch(declarationPart);
      final bool callbackName =
          cachedRegExp(r'^on[A-Z_]').hasMatch(name) ||
          cachedRegExp(
            r'(?:callback|hook|customiz(?:e|er)|transform|decorator|factory|builder|handler|interceptor|strategy)',
            caseSensitive: false,
          ).hasMatch(name);

      final bool invoked = cachedRegExp(
        '\\b${RegExp.escape(name)}\\s*(?:(?:\\?|!)\\s*\\.\\s*)?(?:(?:call|Invoke)\\s*)?\\(',
      ).hasMatch(body);
      if (optional && _identifierCount(body, name) > 0) {
        parameters.add(
          _OptionalParameter(
            name: name,
            positionalIndex: positionalIndex,
            named: named,
            callbackLike: callbackName,
            invoked: invoked,
          ),
        );
      }
      if (!named) positionalIndex++;
    }
  }
  return parameters;
}

Iterable<List<String>> _callArguments(String source, String name) =>
    _callArgumentsInCode(_codeWithoutCommentsAndStrings(source), name);

Iterable<List<String>> _callArgumentsInCode(String code, String name) sync* {
  final RegExp call = cachedRegExp('\\b${RegExp.escape(name)}\\s*\\(');
  for (final RegExpMatch match in call.allMatches(code)) {
    var cursor = match.start - 1;
    while (cursor >= 0 && code[cursor].trim().isEmpty) {
      cursor--;
    }
    if (cursor >= 0 && code[cursor] == '.') {
      final String receiver = code.substring(0, cursor).trimRight();
      if (!cachedRegExp(r'(?:this|self)$').hasMatch(receiver)) continue;
    }
    final int open = code.indexOf('(', match.start);
    final int close = _matchingDelimiter(code, open, '(', ')');
    if (close == -1) continue;
    final String arguments = code.substring(open + 1, close);
    if (arguments.trim().isEmpty) {
      yield const <String>[];
      continue;
    }
    yield _splitTopLevel(
      arguments,
    ).map((String argument) => argument.trim()).toList(growable: false);
  }
}

String? _simpleConstant(String argument) {
  final String normalized = argument.replaceAll(cachedRegExp(r'\s+'), '');
  if (cachedRegExp(
    r'^(?:true|false|True|False|null|None|nil|-?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))$',
  ).hasMatch(normalized)) {
    return normalized;
  }
  if (cachedRegExp(
    r'^(?:[A-Z][A-Za-z0-9_$]*\.)+[A-Za-z_$][\w$]*$|^[A-Z][A-Z0-9_]*$',
  ).hasMatch(normalized)) {
    return normalized;
  }
  return null;
}

int _identifierCount(String source, String identifier) => cachedRegExp(
  '\\b${RegExp.escape(identifier)}\\b',
).allMatches(source).length;

RegExpMatch? _directForwardingCall(String tail) {
  final String? expression = _directReturnedExpression(tail);
  if (expression == null) return null;
  return cachedRegExp(
    r'^(?:(?:this|self)\.)?([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$',
    multiLine: true,
  ).firstMatch(expression);
}

String? _directReturnedExpression(String tail) {
  var body = tail.trim();
  if (body.startsWith('async ')) body = body.substring(6).trim();
  if (body.startsWith('=>')) {
    body = body.substring(2).trim();
  } else if (body.startsWith('{')) {
    if (!body.endsWith('}')) return null;
    body = body.substring(1, body.length - 1).trim();
  } else if (body.startsWith('->')) {
    final int colon = body.indexOf(':');
    final int brace = body.indexOf('{');
    if (colon != -1 && (brace == -1 || colon < brace)) {
      body = body.substring(colon + 1).trim();
    } else {
      if (brace == -1 || !body.endsWith('}')) return null;
      body = body.substring(brace + 1, body.length - 1).trim();
    }
  } else if (body.startsWith(':')) {
    final int brace = body.indexOf('{');
    if (brace == -1) {
      body = body.substring(1).trim();
    } else {
      if (!body.endsWith('}')) return null;
      body = body.substring(brace + 1, body.length - 1).trim();
    }
  } else {
    final int brace = body.indexOf('{');
    if (brace == -1 || !body.endsWith('}')) return null;
    final String returnType = body.substring(0, brace).trim();
    if (returnType.isEmpty || cachedRegExp(r'[;=]').hasMatch(returnType)) {
      return null;
    }
    body = body.substring(brace + 1, body.length - 1).trim();
  }
  if (body.startsWith('return ')) body = body.substring(7).trim();
  if (body.startsWith('await ')) body = body.substring(6).trim();
  if (body.endsWith(';')) body = body.substring(0, body.length - 1).trim();
  return body;
}

List<String>? _forwardedParameterNames(String source, {required String path}) {
  final String? language = _sourceLanguage(path);
  final List<String> result = <String>[];
  for (final String raw in _splitTopLevel(source)) {
    var parameter = raw.trim();
    if (parameter.isEmpty || (language == 'cpp' && parameter == 'void')) {
      continue;
    }
    parameter = parameter.replaceAll(cachedRegExp(r'^[\s{\[]+|[\s}\]]+$'), '');
    final int equals = parameter.indexOf('=');
    if (equals != -1) parameter = parameter.substring(0, equals).trim();
    if (cachedRegExp(r'[\(\{\[]').hasMatch(parameter)) return null;

    final int colon = parameter.indexOf(':');
    final String nameSource = colon == -1
        ? parameter
        : parameter.substring(0, colon);
    final List<RegExpMatch> identifiers = cachedRegExp(
      r'[A-Za-z_$][\w$]*',
    ).allMatches(nameSource).toList(growable: false);
    if (identifiers.isEmpty) return null;
    final String name = language == 'go'
        ? identifiers.first.group(0)!
        : identifiers.last.group(0)!;
    if (name == 'this' || name == 'self') continue;
    result.add(name);
  }
  return result;
}

List<String> _splitTopLevel(String source) {
  final List<String> result = <String>[];
  var start = 0;
  var depth = 0;
  for (var index = 0; index < source.length; index++) {
    switch (source[index]) {
      case '(':
      case '[':
      case '{':
      case '<':
        depth++;
      case ')':
      case ']':
      case '}':
      case '>':
        depth--;
      case ',':
        if (depth == 0) {
          result.add(source.substring(start, index));
          start = index + 1;
        }
    }
  }
  result.add(source.substring(start));
  return result;
}

int _matchingDelimiter(
  String source,
  int open,
  String opening,
  String closing,
) {
  var depth = 0;
  for (var index = open; index < source.length; index++) {
    if (source[index] == opening) depth++;
    if (source[index] == closing && --depth == 0) return index;
  }
  return -1;
}

String _codeWithoutCommentsAndStrings(String source) {
  final StringBuffer code = StringBuffer();
  var inBlockComment = false;
  for (final String line in source.split('\n')) {
    final ({String source, bool endsInBlockComment}) stripped = _stripComments(
      _stripStringLiterals(line),
      inBlockComment: inBlockComment,
    );
    inBlockComment = stripped.endsInBlockComment;
    code.writeln(stripped.source);
  }
  return code.toString();
}

bool _callsFunction(String source, String name) => cachedRegExp(
  '\\b(?:(?:this|self)\\s*\\.\\s*)?${RegExp.escape(name)}\\s*\\(',
).hasMatch(_codeWithoutCommentsAndStrings(source));
