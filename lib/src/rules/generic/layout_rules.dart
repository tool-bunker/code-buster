// Whitespace, line length, tabs, TODOs, and save-time operations are formatting concerns that can be checked without understanding a language AST.

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../../core/models.dart';
import '../../core/rule.dart';

/// Canonical metadata owned by repository layout rules.
final Map<String, RuleMetadata> layoutRuleMetadata = <String, RuleMetadata>{
  'long-line': const RuleMetadata(
    id: 'long-line',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'Wrap line',
    why: 'A line exceeds the recommended style length.',
    suggestion: 'Wrap the expression using the language formatter.',
    version: 2,
    limitations: <String>[
      'Dart is excluded because dart format may intentionally exceed its page width.',
    ],
  ),
  'tab-indent': const RuleMetadata(
    id: 'tab-indent',
    defaultSeverity: RuleSeverity.warn,
    group: 'core',
    title: 'Replace tabs',
    why: 'A line contains a tab character.',
    suggestion: 'Replace indentation tabs with spaces.',
    version: 5,
    limitations: <String>[
      'At most 50 deterministic file findings are retained per run.',
      'Dart tabs inside string values are not indentation findings.',
      'EditorConfig section ordering and extension overrides are honored.',
      'Other languages require formatter or editor evidence that spaces are enforced.',
    ],
  ),
  'trailing-whitespace': const RuleMetadata(
    id: 'trailing-whitespace',
    defaultSeverity: RuleSeverity.info,
    group: 'core',
    title: 'Trim whitespace',
    why: 'A line has trailing whitespace.',
    suggestion: 'Trim trailing spaces before committing.',
    version: 3,
    limitations: <String>[
      'At most 50 deterministic file findings are retained per run.',
      'Non-Dart source requires applicable EditorConfig or Prettier evidence.',
    ],
  ),
};

/// Executable language-neutral tab-indentation rule.
final class TabIndentRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const TabIndentRule();

  @override
  RuleMetadata get metadata => layoutRuleMetadata['tab-indent']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    var emitted = 0;
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (emitted >= 50) return;
      final bool dart = source.key.endsWith('.dart');
      if (!dart && !tabsForbidden(source.key, context.config)) continue;
      final List<String> lines = context.linesFor(source.key);
      final List<int> matches = dart
          ? _dartTabIndentLines(lines)
          : _tabIndentLines(lines, source.key);
      if (matches.isNotEmpty) {
        emitted++;
        yield _layoutFinding(
          metadata: metadata,
          path: source.key,
          line: matches.first,
          message: matches.length == 1
              ? 'tab character used for indentation/alignment'
              : 'tab characters used on ${matches.length} lines',
          why:
              'Tabs render differently across editors and many project styles forbid tab indentation.',
          suggestion: 'Use spaces for indentation.',
          relatedFiles: matches
              .skip(1)
              .map((int line) => '${source.key}:$line')
              .toList(growable: false),
        );
      }
    }
  }
}

/// Executable language-neutral trailing-whitespace rule.
final class TrailingWhitespaceRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const TrailingWhitespaceRule();

  static final RegExp _trailingWhitespace = RegExp(r'[ \t]$');

  @override
  RuleMetadata get metadata => layoutRuleMetadata['trailing-whitespace']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    var emitted = 0;
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (emitted >= 50) return;
      final bool dart = source.key.endsWith('.dart');
      if (!dart && !trailingWhitespaceForbidden(source.key, context.config)) {
        continue;
      }
      final List<String> lines = context.linesFor(source.key);
      final List<int> matches = dart
          ? _dartTrailingWhitespaceLines(lines, _trailingWhitespace)
          : <int>[
              for (var index = 0; index < lines.length; index++)
                if (lines[index].isNotEmpty &&
                    _trailingWhitespace.hasMatch(lines[index]))
                  index + 1,
            ];
      if (matches.isNotEmpty) {
        emitted++;
        yield _layoutFinding(
          metadata: metadata,
          path: source.key,
          line: matches.first,
          message: matches.length == 1
              ? 'line has trailing whitespace'
              : '${matches.length} lines have trailing whitespace',
          why: 'Trailing whitespace creates noisy diffs.',
          suggestion: 'Trim trailing spaces before committing.',
          relatedFiles: matches
              .skip(1)
              .map((int line) => '${source.key}:$line')
              .toList(growable: false),
        );
      }
    }
  }
}

/// Executable language-neutral line-length rule.
final class LongLineRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const LongLineRule();

  @override
  RuleMetadata get metadata => layoutRuleMetadata['long-line']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (source.key.endsWith('.dart')) continue;
      final int lineLimit = genericLineLimit(source.key, context.config);
      final List<String> lines = context.linesFor(source.key);
      final bool templateLanguage = RegExp(
        r'\.(?:js|jsx|mjs|cjs|ts|tsx)$',
      ).hasMatch(source.key);
      var inTemplate = false;
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index];
        final bool startedInTemplate = inTemplate;
        if (templateLanguage &&
            RegExp(r'(?<!\\)`').allMatches(raw).length.isOdd) {
          inTemplate = !inTemplate;
        }
        final bool templateContent = startedInTemplate || inTemplate;
        final String trimmed = raw.trimLeft();
        final bool unwrappable =
            trimmed.startsWith('//') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('#') ||
            trimmed.startsWith('import ') ||
            trimmed.startsWith('export ') ||
            trimmed.contains("'") ||
            trimmed.contains('"') ||
            trimmed.contains('`');
        if (lineLimit > 0 &&
            raw.length > lineLimit &&
            !unwrappable &&
            !templateContent) {
          yield _layoutFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'line length ${raw.length} > $lineLimit',
            why: 'Shorter lines are easier to scan and review.',
            suggestion:
                'Wrap the expression/call using normal language indentation conventions.',
          );
        }
      }
    }
  }
}

List<int> _tabIndentLines(List<String> lines, String sourcePath) {
  final List<int> matches = <int>[];
  final bool templateLanguage = RegExp(
    r'\.(?:js|jsx|mjs|cjs|ts|tsx)$',
  ).hasMatch(sourcePath);
  final bool lua = RegExp(r'\.(?:lua|luau)$').hasMatch(sourcePath);
  var inTemplate = false;
  var inBlockComment = false;
  String? luaLongString;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    final bool contentLine =
        inTemplate || inBlockComment || luaLongString != null;
    if (!contentLine && RegExp(r'^[ ]*\t').hasMatch(line)) {
      matches.add(index + 1);
    }

    if (templateLanguage && RegExp(r'(?<!\\)`').allMatches(line).length.isOdd) {
      inTemplate = !inTemplate;
    }
    if (lua) {
      if (luaLongString != null) {
        if (line.contains(']$luaLongString]')) luaLongString = null;
      } else {
        final Match? opening = RegExp(r'\[(=*)\[').firstMatch(line);
        if (opening != null) {
          final String equals = opening.group(1)!;
          if (!line.substring(opening.end).contains(']$equals]')) {
            luaLongString = equals;
          }
        }
      }
    }
    if (inBlockComment) {
      if (line.contains('*/')) inBlockComment = false;
    } else {
      final int opening = line.indexOf('/*');
      if (opening >= 0 && line.indexOf('*/', opening + 2) < 0) {
        inBlockComment = true;
      }
    }
  }
  return matches;
}

List<int> _dartTabIndentLines(List<String> lines) {
  final List<int> matches = <int>[];
  String? tripleQuote;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    final bool insideTripleString = tripleQuote != null;
    tripleQuote = _nextDartTripleQuote(line, tripleQuote);
    final String trimmed = line.trimLeft();
    final bool commentLine =
        trimmed.startsWith('//') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('*');
    if (!insideTripleString &&
        tripleQuote == null &&
        !commentLine &&
        line.substring(0, line.length - trimmed.length).contains('\t')) {
      matches.add(index + 1);
    }
  }
  return matches;
}

List<int> _dartTrailingWhitespaceLines(
  List<String> lines,
  RegExp trailingWhitespace,
) {
  final List<int> matches = <int>[];
  String? tripleQuote;
  for (var index = 0; index < lines.length; index++) {
    final String line = lines[index];
    final bool insideTripleString = tripleQuote != null;
    tripleQuote = _nextDartTripleQuote(line, tripleQuote);
    if (!insideTripleString &&
        tripleQuote == null &&
        line.isNotEmpty &&
        trailingWhitespace.hasMatch(line)) {
      matches.add(index + 1);
    }
  }
  return matches;
}

String? _nextDartTripleQuote(String line, String? tripleQuote) {
  for (final String delimiter in <String>["'''", '"""']) {
    if (delimiter.allMatches(line).length.isOdd) {
      tripleQuote = tripleQuote == null ? delimiter : null;
    }
  }
  return tripleQuote;
}

Finding _layoutFinding({
  required RuleMetadata metadata,
  required String path,
  required int line,
  required String message,
  required String why,
  required String suggestion,
  List<String> relatedFiles = const <String>[],
}) => Finding(
  code: metadata.id,
  severity: metadata.defaultSeverity,
  path: path,
  line: line,
  endLine: line,
  message: message,
  confidence: 'high',
  why: why,
  suggestion: suggestion,
  relatedFiles: relatedFiles,
);

/// Returns the formatter-backed maximum line width, or zero without evidence.
int genericLineLimit(String sourcePath, AnalysisConfig? config) {
  final int? configured = _configuredLineLimit(sourcePath, config);
  if (configured != null) return configured;
  // A language's conventional formatter is not evidence that this repository
  // enforces a particular width. Only an applicable project policy enables it.
  return 0;
}

int? _configuredLineLimit(String sourcePath, AnalysisConfig? config) =>
    _biomeLineLimit(sourcePath, config) ??
    _prettierLineLimit(sourcePath, config) ??
    _editorConfigLineLimit(sourcePath, config);

int? _prettierLineLimit(String sourcePath, AnalysisConfig? config) {
  if (config == null) return null;
  final String root = p.normalize(p.absolute(config.root));
  var directory = p.dirname(p.join(root, sourcePath));
  while (directory == root || p.isWithin(root, directory)) {
    for (final String name in const <String>[
      '.prettierrc',
      '.prettierrc.json',
      '.prettierrc.js',
      'prettier.config.js',
    ]) {
      final File file = File(p.join(directory, name));
      if (!file.existsSync()) continue;
      final RegExpMatch? match = RegExp(
        r'''(?:["']?printWidth["']?\s*[:=]\s*)(\d+)''',
      ).firstMatch(file.readAsStringSync());
      if (match != null) return int.parse(match.group(1)!);
    }
    if (directory == root) break;
    directory = p.dirname(directory);
  }
  return null;
}

int? _editorConfigLineLimit(String sourcePath, AnalysisConfig? config) {
  if (config == null) return null;
  final String root = p.normalize(p.absolute(config.root));
  var directory = p.dirname(p.join(root, sourcePath));
  while (directory == root || p.isWithin(root, directory)) {
    final File editorConfig = File(p.join(directory, '.editorconfig'));
    if (editorConfig.existsSync()) {
      var applies = true;
      int? selected;
      final String name = p.basename(sourcePath).toLowerCase();
      final String extension = p.extension(name).replaceFirst('.', '');
      for (final String raw in editorConfig.readAsLinesSync()) {
        final String line = raw.trim();
        if (line.startsWith('[') && line.endsWith(']')) {
          final String pattern = line
              .substring(1, line.length - 1)
              .toLowerCase();
          applies =
              pattern == '*' ||
              pattern == '*.*' ||
              pattern == '*.$extension' ||
              (pattern.startsWith('*.{') &&
                  pattern.endsWith('}') &&
                  pattern
                      .substring(3, pattern.length - 1)
                      .split(',')
                      .contains(extension));
          continue;
        }
        final RegExpMatch? match = RegExp(
          r'^max_line_length\s*=\s*(\d+|off)$',
          caseSensitive: false,
        ).firstMatch(line);
        if (applies && match != null) {
          final String value = match.group(1)!.toLowerCase();
          selected = value == 'off' ? 0 : int.parse(value);
        }
      }
      if (selected != null) return selected;
    }
    if (directory == root) break;
    directory = p.dirname(directory);
  }
  return null;
}

int? _biomeLineLimit(String sourcePath, AnalysisConfig? config) {
  if (config == null) return null;
  final String root = p.normalize(p.absolute(config.root));
  var directory = p.dirname(p.join(root, sourcePath));
  while (directory == root || p.isWithin(root, directory)) {
    final File biome = File(p.join(directory, 'biome.json'));
    if (biome.existsSync()) {
      try {
        final Object? value = jsonDecode(biome.readAsStringSync());
        if (value is Map<String, dynamic>) {
          final Object? formatter = value['formatter'];
          if (formatter is Map<String, dynamic>) {
            if (formatter['enabled'] == false) return 0;
            final Object? width = formatter['lineWidth'];
            if (width is int && width > 0) return width;
          }
        }
      } on FormatException {
        return null;
      }
    }
    if (directory == root) break;
    directory = p.dirname(directory);
  }
  return null;
}

/// Whether applicable repository formatting policy forbids trailing whitespace.
bool trailingWhitespaceForbidden(String sourcePath, AnalysisConfig? config) {
  if (config == null) return false;
  final String root = p.normalize(p.absolute(config.root));
  var directory = p.dirname(p.join(root, sourcePath));
  while (directory == root || p.isWithin(root, directory)) {
    for (final String name in const <String>[
      '.prettierrc',
      '.prettierrc.json',
      '.prettierrc.js',
      'prettier.config.js',
    ]) {
      if (File(p.join(directory, name)).existsSync()) return true;
    }
    final File editorConfig = File(p.join(directory, '.editorconfig'));
    if (editorConfig.existsSync()) {
      var applies = true;
      bool? selected;
      final String name = p.basename(sourcePath).toLowerCase();
      final String extension = p.extension(name).replaceFirst('.', '');
      for (final String raw in editorConfig.readAsLinesSync()) {
        final String line = raw.trim();
        if (line.startsWith('[') && line.endsWith(']')) {
          final String pattern = line
              .substring(1, line.length - 1)
              .toLowerCase();
          applies =
              pattern == '*' ||
              pattern == '*.*' ||
              pattern == '*.$extension' ||
              (pattern.startsWith('*.{') &&
                  pattern.endsWith('}') &&
                  pattern
                      .substring(3, pattern.length - 1)
                      .split(',')
                      .contains(extension));
          continue;
        }
        final RegExpMatch? match = RegExp(
          r'^trim_trailing_whitespace\s*=\s*(true|false)$',
          caseSensitive: false,
        ).firstMatch(line);
        if (applies && match != null) {
          selected = match.group(1)!.toLowerCase() == 'true';
        }
      }
      if (selected != null) return selected;
    }
    if (directory == root) break;
    directory = p.dirname(directory);
  }
  return false;
}

/// Whether applicable repository formatting policy requires space indentation.
bool tabsForbidden(String sourcePath, AnalysisConfig? config) {
  // gofmt defines tab indentation as the language-standard representation.
  if (sourcePath.toLowerCase().endsWith('.go') || config == null) return false;
  final String root = p.normalize(p.absolute(config.root));
  var directory = p.dirname(p.join(root, sourcePath));
  while (directory == root || p.isWithin(root, directory)) {
    for (final String name in const <String>[
      '.prettierrc',
      '.prettierrc.json',
      '.prettierrc.js',
      'prettier.config.js',
    ]) {
      final File prettier = File(p.join(directory, name));
      if (!prettier.existsSync()) continue;
      final String source = prettier.readAsStringSync();
      try {
        final Object? value = jsonDecode(source);
        if (value is Map<String, dynamic>) return value['useTabs'] != true;
      } on FormatException {
        final RegExpMatch? useTabs = RegExp(
          r'''useTabs\s*[:=]\s*(true|false)''',
        ).firstMatch(source);
        return useTabs?.group(1) != 'true';
      }
    }
    final File editorConfig = File(p.join(directory, '.editorconfig'));
    if (editorConfig.existsSync()) {
      var applies = true;
      bool? selected;
      final String name = p.basename(sourcePath).toLowerCase();
      final String extension = p.extension(name).replaceFirst('.', '');
      for (final String raw in editorConfig.readAsLinesSync()) {
        final String line = raw.trim();
        if (line.startsWith('[') && line.endsWith(']')) {
          final String pattern = line
              .substring(1, line.length - 1)
              .toLowerCase();
          applies =
              pattern == '*' ||
              pattern == '*.*' ||
              pattern == '*.$extension' ||
              (pattern.startsWith('*.{') &&
                  pattern.endsWith('}') &&
                  pattern
                      .substring(3, pattern.length - 1)
                      .split(',')
                      .contains(extension));
          continue;
        }
        final RegExpMatch? match = RegExp(
          r'^indent_style\s*=\s*(space|tab)$',
          caseSensitive: false,
        ).firstMatch(line);
        if (applies && match != null) {
          selected = match.group(1)!.toLowerCase() == 'space';
        }
      }
      if (selected != null) return selected;
    }
    if (directory == root) break;
    directory = p.dirname(directory);
  }
  return false;
}
