// Language-neutral source risks—comments, conditions, commands, numbers, and suspicious literals—are evaluated here with shared masking.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Canonical metadata owned by the executable generic rules.
final Map<String, RuleMetadata>
genericExecutableRuleMetadata = <String, RuleMetadata>{
  for (final String id in const <String>[
    'fixme-comment',
    'large-inline-list',
    'large-number-ungrouped',
    'needless-bool-branch',
    'operation-on-same-value',
    'suspicious-command-arg-space',
    'todo-comment',
  ])
    id: RuleMetadata(
      id: id,
      version: id == 'operation-on-same-value'
          ? 10
          : id == 'large-inline-list'
          ? 2
          : id == 'large-number-ungrouped'
          ? 3
          : const <String>{'fixme-comment', 'todo-comment'}.contains(id)
          ? 2
          : 1,
      defaultSeverity:
          const <String>{
            'fixme-comment',
            'operation-on-same-value',
            'suspicious-command-arg-space',
          }.contains(id)
          ? RuleSeverity.warn
          : RuleSeverity.info,
      group: 'suspicious',
      title: 'Review ${id.replaceAll('-', ' ')}',
      why:
          'This pattern often indicates unfinished, redundant, or error-prone code.',
      suggestion: 'Clarify the intent or replace the suspicious construct.',
    ),
};

/// Executable rule for TODO markers in source comments.
final class TodoCommentRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const TodoCommentRule();

  static final RegExp _leadingMarker = RegExp(
    r'^\s*\*?\s*todo(?=$|[\s:(])',
    caseSensitive: false,
    multiLine: true,
  );

  @override
  RuleMetadata get metadata => genericExecutableRuleMetadata['todo-comment']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      final _GenericCommentSyntax syntax = _genericCommentSyntax(source.key);
      var inBlockComment = false;
      String? multilineString;
      for (var index = 0; index < lines.length; index++) {
        final scan = _extractGenericComments(
          lines[index],
          syntax: syntax,
          inBlockComment: inBlockComment,
          multilineString: multilineString,
        );
        inBlockComment = scan.inBlockComment;
        multilineString = scan.multilineString;
        if (_leadingMarker.hasMatch(scan.comments)) {
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'TODO marker left in source',
            confidence: 'high',
          );
        }
      }
    }
  }
}

/// Executable rule for FIXME markers in source comments.
final class FixmeCommentRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const FixmeCommentRule();

  static final RegExp _leadingMarker = RegExp(
    r'^\s*\*?\s*fixme(?=$|[\s:(])',
    caseSensitive: false,
    multiLine: true,
  );

  @override
  RuleMetadata get metadata => genericExecutableRuleMetadata['fixme-comment']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      final _GenericCommentSyntax syntax = _genericCommentSyntax(source.key);
      var inBlockComment = false;
      String? multilineString;
      for (var index = 0; index < lines.length; index++) {
        final scan = _extractGenericComments(
          lines[index],
          syntax: syntax,
          inBlockComment: inBlockComment,
          multilineString: multilineString,
        );
        inBlockComment = scan.inBlockComment;
        multilineString = scan.multilineString;
        if (_leadingMarker.hasMatch(scan.comments)) {
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'FIXME marker left in source',
            confidence: 'high',
          );
        }
      }
    }
  }
}

/// Executable rule for comparisons whose operands are the same identifier.
final class OperationOnSameValueRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const OperationOnSameValueRule();

  static final RegExp _comparison = RegExp(
    r'(?<!\.)\b([A-Za-z_]\w*)\s+(==|!=|<=|>=|<|>)\s+\1\b(?!\s*(?:[.\[]|->))',
  );
  static final RegExp _leadingCast = RegExp(
    r'(?:\(\s*(?:(?:const|volatile|signed|unsigned|struct)\s+)*[A-Za-z_]\w*(?:\s*[*&]\s*)*\s*\)\s*)+$',
  );
  static final RegExp _nanContext = RegExp(r'\bnan\b', caseSensitive: false);

  static bool _insideAssertionInvocation(String source, int offset) {
    var nestedClosers = 0;
    for (var index = offset - 1; index >= 0; index--) {
      final int unit = source.codeUnitAt(index);
      if (unit == 0x29) {
        nestedClosers++;
        continue;
      }
      if (unit != 0x28) continue;
      if (nestedClosers > 0) {
        nestedClosers--;
        continue;
      }

      var end = index;
      while (end > 0) {
        final int previous = source.codeUnitAt(end - 1);
        if (previous != 0x20 && previous != 0x09) break;
        end--;
      }
      var start = end;
      while (start > 0) {
        final int previous = source.codeUnitAt(start - 1);
        final bool identifier =
            (previous >= 0x30 && previous <= 0x39) ||
            (previous >= 0x41 && previous <= 0x5a) ||
            previous == 0x5f ||
            (previous >= 0x61 && previous <= 0x7a);
        if (!identifier) break;
        start--;
      }
      if (start == end) continue;
      final String name = source.substring(start, end).toLowerCase();
      if (name == 'assert' ||
          name.startsWith('assert_') ||
          name.endsWith('assert') ||
          name.contains('_assert_') ||
          name == 'expect' ||
          name.startsWith('expect_')) {
        return true;
      }
    }
    return false;
  }

  static bool _hasFloatingPointDeclaration(
    List<String> lines,
    int lineIndex,
    String identifier,
  ) {
    final RegExp declaration = RegExp(
      '\\b(?:float|double)\\s+(?:[*&]\\s*)?${RegExp.escape(identifier)}\\b',
    );
    final int firstLine = lineIndex > 20 ? lineIndex - 20 : 0;
    for (var index = lineIndex; index >= firstLine; index--) {
      final String code = stripGenericRuleStrings(lines[index]);
      if (declaration.hasMatch(code)) return true;
      if (index != lineIndex && RegExp(r'^\s*}\s*$').hasMatch(code)) break;
    }
    return false;
  }

  static bool _hasNaNContext(List<String> lines, int lineIndex) {
    final int firstLine = lineIndex > 2 ? lineIndex - 2 : 0;
    for (var index = lineIndex; index >= firstLine; index--) {
      if (_nanContext.hasMatch(stripGenericRuleStrings(lines[index]))) {
        return true;
      }
      if (index != lineIndex && RegExp(r'^\s*}\s*$').hasMatch(lines[index])) {
        break;
      }
    }
    return false;
  }

  static bool _hasFollowingNaNGuard(List<String> lines, int lineIndex) {
    final int lastLine = (lineIndex + 4).clamp(0, lines.length - 1);
    for (var index = lineIndex + 1; index <= lastLine; index++) {
      if (RegExp(
        r'\b(?:unexpected\s+nan|nan\s+cannot\s+equal)\b',
        caseSensitive: false,
      ).hasMatch(lines[index])) {
        return true;
      }
    }
    return false;
  }

  static bool _isNaNTernaryComparison(
    List<String> lines,
    int lineIndex,
    String operator,
  ) {
    final String code = stripGenericRuleStrings(lines[lineIndex]).trim();
    final RegExp notEqual = RegExp(r'\b([A-Za-z_]\w*)\s*!=\s*\1\s*$');
    final RegExp equalTernary = RegExp(r'^\?\s*([A-Za-z_]\w*)\s*==\s*\1\b');
    if (operator == '!=' && lineIndex + 1 < lines.length) {
      final RegExpMatch? notEqualMatch = notEqual.firstMatch(code);
      final RegExpMatch? equalMatch = equalTernary.firstMatch(
        stripGenericRuleStrings(lines[lineIndex + 1]).trim(),
      );
      return notEqualMatch != null &&
          equalMatch != null &&
          notEqualMatch.group(1) != equalMatch.group(1);
    }
    if (operator == '==' && lineIndex > 0) {
      final RegExpMatch? equalMatch = equalTernary.firstMatch(code);
      final RegExpMatch? notEqualMatch = notEqual.firstMatch(
        stripGenericRuleStrings(lines[lineIndex - 1]).trim(),
      );
      return equalMatch != null &&
          notEqualMatch != null &&
          equalMatch.group(1) != notEqualMatch.group(1);
    }
    return false;
  }

  static bool _hasNoSelfCompareDirective(List<String> lines, int lineIndex) =>
      lineIndex > 0 &&
      RegExp(
        r'\bno-self-compare\b',
        caseSensitive: false,
      ).hasMatch(lines[lineIndex - 1]);

  @override
  RuleMetadata get metadata =>
      genericExecutableRuleMetadata['operation-on-same-value']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (source.key.endsWith('.css')) continue;
      final List<String> lines = context.linesFor(source.key);
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) scanned =
            _stripGenericComments(
              stripGenericRuleStrings(lines[index]),
              inBlockComment: inBlockComment,
            );
        inBlockComment = scanned.inBlockComment;
        final RegExpMatch? match = _comparison.firstMatch(scanned.code);
        if (match == null) continue;
        final String operator = match.group(2)!;
        if ((operator == '==' || operator == '!=') &&
            (_hasFloatingPointDeclaration(lines, index, match.group(1)!) ||
                _hasNaNContext(lines, index) ||
                _hasFollowingNaNGuard(lines, index) ||
                _hasNoSelfCompareDirective(lines, index) ||
                _isNaNTernaryComparison(lines, index, operator))) {
          continue;
        }
        final String prefix = scanned.code
            .substring(0, match.start)
            .trimRight();
        if ((prefix.isNotEmpty &&
                ('&|^+-*/%!<>'.contains(prefix[prefix.length - 1]) ||
                    prefix.endsWith('.'))) ||
            _leadingCast.hasMatch(prefix) ||
            _insideAssertionInvocation(scanned.code, match.start)) {
          continue;
        }
        yield _genericFinding(
          metadata: metadata,
          path: source.key,
          line: index + 1,
          message: 'operation compares ${match.group(1)} with itself',
          confidence: 'high',
        );
      }
    }
  }
}

/// Executable rule for hard-to-read large numeric literals.
final class LargeNumberUngroupedRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const LargeNumberUngroupedRule();

  static final RegExp _number = RegExp(r'(?<![\d.])\d{7,}(?![\d.])');
  static bool _isLegacyOctalInteger(String literal) {
    if (literal.length < 2 || literal.codeUnitAt(0) != 0x30) return false;
    for (var index = 1; index < literal.length; index++) {
      if (literal.codeUnitAt(index) > 0x37) return false;
    }
    return true;
  }

  static final RegExp _url = RegExp(
    r'''(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>"']+''',
    caseSensitive: false,
  );
  static final RegExp _commitLink = RegExp(
    r'''<a\b[^>]*\bhref\s*=\s*["'][^"']*/commit/([0-9a-f]{7,40})(?:[/?#][^"']*)?["'][^>]*>\s*([0-9a-f]{7,40})\s*</a>''',
    caseSensitive: false,
  );

  static bool _isInsideUrl(String line, int start, int end) => _url
      .allMatches(line)
      .any((RegExpMatch url) => start >= url.start && end <= url.end);

  static bool _isCommitHashLinkLabel(String line, String literal) {
    for (final RegExpMatch link in _commitLink.allMatches(line)) {
      final String hash = link.group(1)!.toLowerCase();
      final String label = link.group(2)!.toLowerCase();
      if (literal.toLowerCase() == label && hash.startsWith(label)) {
        return true;
      }
    }
    return false;
  }

  @override
  RuleMetadata get metadata =>
      genericExecutableRuleMetadata['large-number-ungrouped']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (_largeNumberDependencyMetadataNames.contains(
        _pathBasename(source.key),
      )) {
        continue;
      }
      if (_usesUnavailableDigitGroupingSyntax(source.key) ||
          _usesHtmlTextSyntax(source.key)) {
        continue;
      }
      final List<String> rawLines = context.linesFor(source.key);
      final List<String> lines = maskGenericRuleStrings(
        maskDefinitelyInactivePreprocessorBranches(rawLines),
        sourcePath: source.key,
      );
      var inBlockComment = false;
      final bool pythonSource = source.key.endsWith('.py');
      String? pythonDocstring;
      for (var index = 0; index < lines.length; index++) {
        if (pythonSource) {
          final String trimmed = lines[index].trimLeft();
          if (pythonDocstring != null) {
            if (trimmed.contains(pythonDocstring)) {
              pythonDocstring = null;
            }
            continue;
          }
          final String? delimiter = _pythonDocstringDelimiter(trimmed);
          if (delimiter != null) {
            if (delimiter.allMatches(trimmed).length.isOdd) {
              pythonDocstring = delimiter;
            }
            continue;
          }
        }
        final ({String code, bool inBlockComment}) scanned =
            _stripGenericComments(lines[index], inBlockComment: inBlockComment);
        inBlockComment = scanned.inBlockComment;
        for (final RegExpMatch number in _number.allMatches(scanned.code)) {
          final String literal = number.group(0)!;
          if (literal.contains('_') ||
              _isLegacyOctalInteger(literal) ||
              _isInsideUrl(rawLines[index], number.start, number.end) ||
              _isCommitHashLinkLabel(rawLines[index], literal)) {
            continue;
          }
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'large numeric literal is not digit-grouped',
            confidence: 'high',
          );
        }
      }
    }
  }
}

String? _pythonDocstringDelimiter(String trimmedLine) {
  if (trimmedLine.startsWith('"""')) return '"""';
  if (trimmedLine.startsWith("'''")) return "'''";
  return null;
}

bool _usesUnavailableDigitGroupingSyntax(String sourcePath) {
  final int dot = sourcePath.lastIndexOf('.');
  if (dot == -1) return false;
  final String extension = sourcePath.substring(dot);
  return extension != '.C' &&
      const <String>{
        '.c',
        '.css',
        '.h',
        '.lua',
        '.m',
      }.contains(extension.toLowerCase());
}

bool _usesHtmlTextSyntax(String sourcePath) {
  final int dot = sourcePath.lastIndexOf('.');
  if (dot == -1) return false;
  return const <String>{
    '.htm',
    '.html',
  }.contains(sourcePath.substring(dot).toLowerCase());
}

/// Executable rule for oversized inline collection literals.
final class LargeInlineListRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const LargeInlineListRule();

  static final RegExp _collection = RegExp(r'[\[\{]([^\]\}]+)[\]\}]');
  static final RegExp _generatedHeader = RegExp(
    r'\bcode generated\b.*\bdo not edit\b',
    caseSensitive: false,
  );

  static bool _isGeneratedSource(List<String> lines) {
    final int lineCount = lines.length < 10 ? lines.length : 10;
    for (var index = 0; index < lineCount; index++) {
      if (_generatedHeader.hasMatch(lines[index])) {
        return true;
      }
    }
    return false;
  }

  @override
  RuleMetadata get metadata =>
      genericExecutableRuleMetadata['large-inline-list']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      if (_isGeneratedSource(lines)) continue;
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) scanned =
            _stripGenericComments(
              stripGenericRuleStrings(lines[index]),
              inBlockComment: inBlockComment,
            );
        inBlockComment = scanned.inBlockComment;
        final RegExpMatch? collection = _collection.firstMatch(scanned.code);
        if (collection != null &&
            ','.allMatches(collection.group(1)!).length >= 12) {
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'large inline collection literal',
            confidence: 'medium',
          );
        }
      }
    }
  }
}

/// Executable rule for process arguments containing embedded spaces.
final class SuspiciousCommandArgumentRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const SuspiciousCommandArgumentRule();

  static final RegExp _commandCall = RegExp(
    r'(?:Process\.(?:run|start)|subprocess\.(?:run|Popen))\s*\(',
  );
  static final RegExp _argumentLiteral = RegExp(
    r'''(?:^|[\[(,])\s*[rRuUbBfF]{0,2}(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')''',
  );
  static final RegExp _whitespace = RegExp(r'\s');

  @override
  RuleMetadata get metadata =>
      genericExecutableRuleMetadata['suspicious-command-arg-space']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) scanned =
            _stripCommandComments(lines[index], inBlockComment: inBlockComment);
        inBlockComment = scanned.inBlockComment;
        final RegExpMatch? call = _commandCall.firstMatch(scanned.code);
        if (call == null) continue;
        final String arguments = scanned.code.substring(call.end);
        final bool hasEmbeddedSpace = _argumentLiteral
            .allMatches(arguments)
            .any((RegExpMatch match) {
              final String literal = match.group(1) ?? match.group(2)!;
              if (!_whitespace.hasMatch(literal)) return false;
              final String preceding = arguments
                  .substring(0, match.start)
                  .trimRight();
              if (preceding.endsWith('.split')) return false;
              final String following = arguments
                  .substring(match.end)
                  .trimLeft();
              return !following.startsWith('.split(');
            });
        if (hasEmbeddedSpace) {
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'command argument appears to contain embedded spaces',
            confidence: 'medium',
          );
        }
      }
    }
  }
}

/// Executable rule for branches that return a boolean condition verbatim.
final class NeedlessBoolBranchRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const NeedlessBoolBranchRule();

  static final RegExp _trueBranch = RegExp(
    r'^\s*if\s*\([^)]*\)\s*(?:return\s+true|\{\s*return\s+true)',
  );
  static final RegExp _falseReturn = RegExp(
    r'^(?:}\s*)*(?:else\s+)?return\s+false\b',
  );
  static final RegExp _conditionalBooleanReturn = RegExp(
    r'^(?:}\s*)*(?:else\s+)?if\b.*\breturn\s+(?:true|false)\b',
  );

  @override
  RuleMetadata get metadata =>
      genericExecutableRuleMetadata['needless-bool-branch']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!_genericRuleEnabled(context.config, metadata.id)) return;
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      for (var index = 0; index < lines.length; index++) {
        if (!_trueBranch.hasMatch(stripGenericRuleStrings(lines[index]))) {
          continue;
        }
        var hasMatchingFalseReturn = false;
        for (final String next in lines.skip(index + 1).take(4)) {
          final String rawCode = next.trim();
          if (rawCode.isEmpty) {
            continue;
          }
          if (_conditionalBooleanReturn.hasMatch(rawCode)) {
            break;
          }
          hasMatchingFalseReturn = _falseReturn.hasMatch(
            stripGenericRuleStrings(rawCode),
          );
          break;
        }
        if (hasMatchingFalseReturn) {
          yield _genericFinding(
            metadata: metadata,
            path: source.key,
            line: index + 1,
            message: 'boolean branch can return its condition directly',
            confidence: 'medium',
          );
        }
      }
    }
  }
}

const Set<String> _largeNumberDependencyMetadataNames = <String>{
  'Cargo.lock',
  'Cargo.toml',
  'Gemfile',
  'Gemfile.lock',
  'Package.resolved',
  'Package.swift',
  'Pipfile',
  'Pipfile.lock',
  'Podfile',
  'Podfile.lock',
  'composer.json',
  'composer.lock',
  'go.mod',
  'go.sum',
  'gradle.lockfile',
  'gradle.properties',
  'npm-shrinkwrap.json',
  'package-lock.json',
  'package.json',
  'packages.lock.json',
  'pnpm-lock.yaml',
  'poetry.lock',
  'pom.xml',
  'pubspec.lock',
  'pubspec.yaml',
  'pyproject.toml',
  'uv.lock',
  'yarn.lock',
};

String _pathBasename(String filePath) {
  final int slash = filePath.lastIndexOf('/');
  final int backslash = filePath.lastIndexOf(r'\');
  final int separator = slash > backslash ? slash : backslash;
  return separator == -1 ? filePath : filePath.substring(separator + 1);
}

typedef _GenericCommentSyntax = ({
  bool slashLine,
  bool slashBlock,
  bool hashLine,
  bool dashLine,
  bool semicolonLine,
  bool percentLine,
});

_GenericCommentSyntax _genericCommentSyntax(String sourcePath) {
  final String lower = sourcePath.toLowerCase();
  final int dot = lower.lastIndexOf('.');
  final String extension = dot == -1 ? '' : lower.substring(dot);
  final String basename = _pathBasename(lower);
  final bool slashLine = const <String>{
    '.c',
    '.cc',
    '.cpp',
    '.cs',
    '.cxx',
    '.dart',
    '.go',
    '.groovy',
    '.h',
    '.hh',
    '.hpp',
    '.java',
    '.js',
    '.jsx',
    '.kt',
    '.kts',
    '.m',
    '.mjs',
    '.mm',
    '.mojo',
    '.php',
    '.rs',
    '.scala',
    '.scss',
    '.swift',
    '.ts',
    '.tsx',
    '.vue',
    '.wren',
  }.contains(extension);
  final bool slashBlock =
      slashLine || const <String>{'.css', '.less', '.sql'}.contains(extension);
  final bool hashLine =
      const <String>{
        '.bash',
        '.fish',
        '.jl',
        '.nim',
        '.pl',
        '.pm',
        '.ps1',
        '.py',
        '.pyi',
        '.r',
        '.rb',
        '.sh',
        '.toml',
        '.yaml',
        '.yml',
        '.zsh',
      }.contains(extension) ||
      const <String>{'dockerfile', 'gemfile', 'makefile'}.contains(basename);
  return (
    slashLine: slashLine,
    slashBlock: slashBlock,
    hashLine: hashLine,
    dashLine: const <String>{
      '.hs',
      '.lua',
      '.luau',
      '.sql',
    }.contains(extension),
    semicolonLine: const <String>{
      '.clj',
      '.cljc',
      '.cljs',
      '.el',
      '.lisp',
    }.contains(extension),
    percentLine: const <String>{'.erl', '.hrl', '.tex'}.contains(extension),
  );
}

({String comments, bool inBlockComment, String? multilineString})
_extractGenericComments(
  String line, {
  required _GenericCommentSyntax syntax,
  required bool inBlockComment,
  required String? multilineString,
}) {
  final StringBuffer comments = StringBuffer();
  var index = 0;
  while (index < line.length) {
    final String? activeString = multilineString;
    if (activeString != null) {
      final int end = line.indexOf(activeString, index);
      if (end == -1) {
        return (
          comments: comments.toString(),
          inBlockComment: inBlockComment,
          multilineString: activeString,
        );
      }
      multilineString = null;
      index = end + activeString.length;
      continue;
    }
    if (inBlockComment) {
      final int end = line.indexOf('*/', index);
      if (end == -1) {
        _appendGenericComment(comments, line.substring(index));
        return (
          comments: comments.toString(),
          inBlockComment: true,
          multilineString: multilineString,
        );
      }
      _appendGenericComment(comments, line.substring(index, end));
      inBlockComment = false;
      index = end + 2;
      continue;
    }

    String? delimiter;
    if (line.startsWith('"""', index)) {
      delimiter = '"""';
    } else if (line.startsWith("'''", index)) {
      delimiter = "'''";
    } else if (line[index] == '`') {
      delimiter = '`';
    }
    if (delimiter != null) {
      final int end = line.indexOf(delimiter, index + delimiter.length);
      if (end == -1) {
        multilineString = delimiter;
        break;
      }
      index = end + delimiter.length;
      continue;
    }

    final String character = line[index];
    if (character == '"' || character == "'") {
      final String quote = character;
      index++;
      var escaped = false;
      while (index < line.length) {
        final String quotedCharacter = line[index];
        if (escaped) {
          escaped = false;
        } else if (quotedCharacter == r'\') {
          escaped = true;
        } else if (quotedCharacter == quote) {
          index++;
          break;
        }
        index++;
      }
      continue;
    }

    final String next = index + 1 < line.length ? line[index + 1] : '';
    if (syntax.slashBlock && character == '/' && next == '*') {
      inBlockComment = true;
      index += 2;
      continue;
    }
    if (syntax.slashLine && character == '/' && next == '/') {
      _appendGenericComment(comments, line.substring(index + 2));
      break;
    }
    if (syntax.hashLine && character == '#') {
      _appendGenericComment(comments, line.substring(index + 1));
      break;
    }
    if (syntax.dashLine && character == '-' && next == '-') {
      _appendGenericComment(comments, line.substring(index + 2));
      break;
    }
    if (syntax.semicolonLine && character == ';') {
      _appendGenericComment(comments, line.substring(index + 1));
      break;
    }
    if (syntax.percentLine && character == '%') {
      _appendGenericComment(comments, line.substring(index + 1));
      break;
    }
    index++;
  }
  return (
    comments: comments.toString(),
    inBlockComment: inBlockComment,
    multilineString: multilineString,
  );
}

void _appendGenericComment(StringBuffer comments, String comment) {
  if (comments.isNotEmpty) comments.writeln();
  comments.write(comment);
}

bool _genericRuleEnabled(AnalysisConfig config, String id) =>
    config.ruleGroups.contains('suspicious') ||
    config.severityOverrides.containsKey(id);

Finding _genericFinding({
  required RuleMetadata metadata,
  required String path,
  required int line,
  required String message,
  required String confidence,
}) => Finding(
  code: metadata.id,
  severity: metadata.defaultSeverity,
  path: path,
  line: line,
  endLine: line,
  message: message,
  confidence: confidence,
  why: metadata.why,
  suggestion: metadata.suggestion,
);

/// Removes ordinary quoted literals before generic textual checks.
String stripGenericRuleStrings(String line) => line.replaceAll(
  RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''),
  '',
);

/// Masks quoted literals while preserving source line boundaries.
///
/// Dart and Python triple-quoted strings can span lines, so they require
/// lexical state that the ordinary single-line masker cannot retain.
List<String> maskGenericRuleStrings(
  List<String> lines, {
  required String sourcePath,
}) {
  if (!sourcePath.endsWith('.dart') && !sourcePath.endsWith('.py')) {
    return lines.map(stripGenericRuleStrings).toList(growable: false);
  }

  final List<String> masked = <String>[];
  String? quote;
  var raw = false;
  var blockCommentDepth = 0;
  for (final String line in lines) {
    final StringBuffer code = StringBuffer();
    var index = 0;
    while (index < line.length) {
      final String character = line[index];
      final String next = index + 1 < line.length ? line[index + 1] : '';
      if (quote != null) {
        final String delimiter = quote;
        if (!raw && character == r'\') {
          code.write(' ');
          index++;
          if (index < line.length) {
            code.write(' ');
            index++;
          }
          continue;
        }
        if (line.startsWith(delimiter, index)) {
          code.write(delimiter.length == 3 ? '   ' : ' ');
          index += delimiter.length;
          quote = null;
          raw = false;
          continue;
        }
        code.write(' ');
        index++;
        continue;
      }
      if (blockCommentDepth > 0) {
        if (character == '/' && next == '*') {
          blockCommentDepth++;
          code.write('/*');
          index += 2;
        } else if (character == '*' && next == '/') {
          blockCommentDepth--;
          code.write('*/');
          index += 2;
        } else {
          code.write(character);
          index++;
        }
        continue;
      }
      if (character == '/' && next == '/') {
        code.write(line.substring(index));
        break;
      }
      if (character == '/' && next == '*') {
        blockCommentDepth = 1;
        code.write('/*');
        index += 2;
        continue;
      }
      if (character == "'" || character == '"') {
        final String tripleQuote = '$character$character$character';
        final String delimiter = line.startsWith(tripleQuote, index)
            ? tripleQuote
            : character;
        quote = delimiter;
        raw =
            index > 0 &&
            (line[index - 1] == 'r' || line[index - 1] == 'R') &&
            (index == 1 || !_isDartIdentifierPart(line.codeUnitAt(index - 2)));
        code.write(delimiter.length == 3 ? '   ' : ' ');
        index += delimiter.length;
        continue;
      }
      code.write(character);
      index++;
    }
    if (quote?.length == 1) {
      quote = null;
      raw = false;
    }
    masked.add(code.toString());
  }
  return masked;
}

bool _isDartIdentifierPart(int codeUnit) =>
    (codeUnit >= 0x30 && codeUnit <= 0x39) ||
    (codeUnit >= 0x41 && codeUnit <= 0x5a) ||
    (codeUnit >= 0x61 && codeUnit <= 0x7a) ||
    codeUnit == 0x5f ||
    codeUnit == 0x24;

({String code, bool inBlockComment}) _stripGenericComments(
  String line, {
  required bool inBlockComment,
}) {
  final StringBuffer code = StringBuffer();
  for (var index = 0; index < line.length; index++) {
    final String character = line[index];
    final String next = index + 1 < line.length ? line[index + 1] : '';
    if (inBlockComment) {
      if (character == '*' && next == '/') {
        inBlockComment = false;
        index++;
      }
      code.write(' ');
      continue;
    }
    if (character == '/' && next == '*') {
      inBlockComment = true;
      code.write(' ');
      index++;
      continue;
    }
    if (character == '/' && next == '/') break;
    code.write(character);
  }
  return (code: code.toString(), inBlockComment: inBlockComment);
}

({String code, bool inBlockComment}) _stripCommandComments(
  String line, {
  required bool inBlockComment,
}) {
  final StringBuffer code = StringBuffer();
  String? quote;
  var escaped = false;
  for (var index = 0; index < line.length; index++) {
    final String character = line[index];
    final String next = index + 1 < line.length ? line[index + 1] : '';
    if (inBlockComment) {
      if (character == '*' && next == '/') {
        inBlockComment = false;
        index++;
      }
      code.write(' ');
      continue;
    }
    if (quote != null) {
      code.write(character);
      if (escaped) {
        escaped = false;
      } else if (character == r'\') {
        escaped = true;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == "'" || character == '"') {
      quote = character;
      code.write(character);
      continue;
    }
    if (character == '/' && next == '*') {
      inBlockComment = true;
      code.write(' ');
      index++;
      continue;
    }
    if ((character == '/' && next == '/') || character == '#') break;
    code.write(character);
  }
  return (code: code.toString(), inBlockComment: inBlockComment);
}
