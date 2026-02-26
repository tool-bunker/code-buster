// Shared analysis passes such as complexity, duplication, flags, and repository structure operate here after language parsing is complete.

import 'dart:io';
import 'dart:math' as math;

import 'package:path/path.dart' as path;

import '../core/models.dart';
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
      final int signals = RegExp(
        r'(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|switch|case|catch)([^A-Za-z0-9_]|$)|&&|\|\|',
      ).allMatches(code).length;
      cyclomatic += signals;
      // Adapter function bodies include their own outer braces. That lexical
      // wrapper is not control-flow nesting and must not inflate every signal.
      cognitive += signals * (1 + math.max(0, depth - 1));
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
      final bool supportsGoto = RegExp(
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
            RegExp(r'^goto\s+[A-Za-z_]\w*\s*;').hasMatch(line)) {
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
          .replaceAll(RegExp(r'^/+|/+$'), '');
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

/// Heuristics that identify feature flag references in source text.
final class FeatureFlagAnalysis {
  /// Finds unique flag references in every source file.
  List<Finding> findings(Map<String, String> sources) {
    final RegExp pattern = RegExp(
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
      final List<String> lines = sources[sourcePath]!.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String line = _stripStringLiterals(lines[index]);
        for (final RegExpMatch match in pattern.allMatches(line)) {
          final String receiver = match.group(2)!;
          final String flag = match.group(3)!;
          final bool hasFeatureSemantics = RegExp(
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
        if (RegExp(
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
  RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' '''.trim()),
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
        (cursor == 1 || !RegExp(r'[A-Za-z0-9_]').hasMatch(source[cursor - 2]));
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
