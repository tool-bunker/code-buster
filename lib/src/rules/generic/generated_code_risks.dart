// Generated-looking code can still reveal maintainability problems; these rules use repository-relative comparisons to avoid punishing normal structure.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Advisory rules for concrete maintainability risks common in generated code.
///
/// These rules report observable source properties. They never infer authorship.
final Map<String, RuleMetadata>
generatedCodeRiskMetadata = <String, RuleMetadata>{
  'excessive-comment-density': const RuleMetadata(
    id: 'excessive-comment-density',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Reduce disproportionate commentary',
    why:
        'A source file has substantially more commentary than comparable files in the same repository, which can obscure the implementation and become stale.',
    suggestion:
        'Keep comments that explain constraints or intent and remove narration or restatements of the code.',
    semanticMaturity: RuleSemanticMaturity.project,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    limitations: <String>[
      'Requires at least five source files with twenty or more substantive lines.',
      'Generated files, tests, and files with fewer than eight comment lines are excluded.',
    ],
  ),
  'narrating-implementation-comment': const RuleMetadata(
    id: 'narrating-implementation-comment',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Remove implementation narration',
    why:
        'Step-by-step narration duplicates control flow rather than explaining a constraint or design decision.',
    suggestion:
        'Delete the narration or replace it with the non-obvious reason the implementation is necessary.',
    semanticMaturity: RuleSemanticMaturity.token,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    limitations: <String>[
      'Only explicit first-person sequencing phrases are reported.',
      'Documentation comments and test sources are excluded.',
    ],
  ),
  'trivial-comment-restatement': const RuleMetadata(
    id: 'trivial-comment-restatement',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Remove code-restating comment',
    why:
        'A comment that repeats the adjacent statement adds maintenance cost without explaining intent.',
    suggestion:
        'Remove the comment or explain the constraint, tradeoff, or reason instead.',
    semanticMaturity: RuleSemanticMaturity.token,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    limitations: <String>[
      'Only narrow return, assignment, increment, and invocation restatements are reported.',
      'Documentation comments and test sources are excluded.',
    ],
  ),
  'single-method-delegating-class': const RuleMetadata(
    id: 'single-method-delegating-class',
    defaultSeverity: RuleSeverity.info,
    group: 'yagni',
    title: 'Review pass-through abstraction',
    why:
        'A class with one dependency and one method that forwards unchanged arguments may add indirection without owning policy.',
    suggestion:
        'Call the dependency directly unless this type owns a deliberate boundary, lifecycle, or future compatibility contract.',
    semanticMaturity: RuleSemanticMaturity.ast,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
    languages: <String>['dart'],
    limitations: <String>[
      'Only compact Dart classes whose complete body is a field, constructor, and expression-bodied method are reported.',
      'Framework annotations and abstract or implementing classes are excluded.',
    ],
  ),
  'parallel-schema-definition': const RuleMetadata(
    id: 'parallel-schema-definition',
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Consolidate parallel schema definitions',
    why:
        'The same substantial string-key contract is declared in multiple files, creating competing sources of truth.',
    suggestion:
        'Give the schema one owner and derive serializers, validators, or adapters from it where practical.',
    semanticMaturity: RuleSemanticMaturity.project,
    taxonomy: <FindingTaxonomy>{
      FindingTaxonomy.architecture,
      FindingTaxonomy.maintainability,
    },
    limitations: <String>[
      'Only map or object literals with at least five identical identifier-like string keys are compared.',
      'Test, fixture, generated, localization, and manifest files are excluded.',
    ],
  ),
};

final RegExp _testPath = RegExp(
  r'(^|/)(?:test|tests|spec|specs|__tests__|fixture|fixtures)(?:/|$)|(?:_test|\.test|\.spec)\.',
);
final RegExp _generatedPath = RegExp(
  r'(^|/)(?:generated|gen)(?:/|$)|\.(?:g|freezed|gr)\.[^.]+$',
);
final RegExp _documentationPath = RegExp(
  r'(^|/)(?:doc|docs|documentation)(?:/|$)|\.(?:md|mdx|rst|txt)$',
);

bool _excludedCommentPath(String path) =>
    _testPath.hasMatch(path) ||
    _generatedPath.hasMatch(path) ||
    _documentationPath.hasMatch(path);

final class _LineFacts {
  const _LineFacts({
    required this.code,
    required this.comment,
    required this.documentation,
  });

  final String code;
  final String comment;
  final bool documentation;
}

List<_LineFacts> _scanLines(String path, List<String> lines) {
  final List<_LineFacts> result = <_LineFacts>[];
  var inBlock = false;
  String? multilineQuote;
  for (final String line in lines) {
    final StringBuffer code = StringBuffer();
    final StringBuffer comment = StringBuffer();
    var documentation = false;
    var index = 0;
    while (index < line.length) {
      if (multilineQuote != null) {
        final int end = line.indexOf(multilineQuote, index);
        if (end < 0) {
          index = line.length;
          continue;
        }
        index = end + multilineQuote.length;
        multilineQuote = null;
        continue;
      }
      if (inBlock) {
        final int end = line.indexOf('*/', index);
        if (end < 0) {
          comment.write(line.substring(index));
          index = line.length;
          continue;
        }
        comment.write(line.substring(index, end));
        index = end + 2;
        inBlock = false;
        continue;
      }
      if (line.startsWith('///', index) || line.startsWith('//!', index)) {
        documentation = true;
        comment.write(line.substring(index + 3));
        break;
      }
      if (line.startsWith('/**', index) || line.startsWith('/*!', index)) {
        documentation = true;
        inBlock = true;
        index += 3;
        continue;
      }
      if (line.startsWith('//', index)) {
        comment.write(line.substring(index + 2));
        break;
      }
      if (line.startsWith('/*', index)) {
        inBlock = true;
        index += 2;
        continue;
      }
      if (_usesHashComments(path) && line[index] == '#') {
        if (index == 0 && line.startsWith('#!')) {
          break;
        }
        comment.write(line.substring(index + 1));
        break;
      }
      if (_usesDashComments(path) && line.startsWith('--', index)) {
        comment.write(line.substring(index + 2));
        break;
      }
      final String character = line[index];
      if (character == '"' || character == "'" || character == '`') {
        final String triple = '$character$character$character';
        if ((path.endsWith('.dart') || path.endsWith('.py')) &&
            line.startsWith(triple, index)) {
          final int end = line.indexOf(triple, index + 3);
          if (end < 0) {
            multilineQuote = triple;
            index = line.length;
          } else {
            index = end + 3;
          }
          continue;
        }
        final String quote = character;
        code.write(' ');
        index++;
        var escaped = false;
        while (index < line.length) {
          final String current = line[index];
          code.write(' ');
          index++;
          if (escaped) {
            escaped = false;
          } else if (current == r'\') {
            escaped = true;
          } else if (current == quote) {
            break;
          }
        }
        continue;
      }
      code.write(character);
      index++;
    }
    result.add(
      _LineFacts(
        code: code.toString(),
        comment: comment.toString(),
        documentation: documentation,
      ),
    );
  }
  return result;
}

bool _usesHashComments(String path) => RegExp(
  r'\.(?:py|pyi|rb|sh|bash|zsh|fish|pl|pm|r|jl|nim|toml|ya?ml)$',
).hasMatch(path.toLowerCase());

bool _usesDashComments(String path) =>
    RegExp(r'\.(?:lua|luau|sql|hs)$').hasMatch(path.toLowerCase());

/// Reports repository-relative outliers rather than imposing a global ratio.
final class ExcessiveCommentDensityRule extends SelfContainedRule {
  /// Creates the repository-level comment-density rule.
  ExcessiveCommentDensityRule()
    : super(generatedCodeRiskMetadata['excessive-comment-density']!);

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final List<({String path, int code, int comments, int first})> files = [];
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (_excludedCommentPath(source.key)) continue;
      final List<_LineFacts> facts = _scanLines(
        source.key,
        context.linesFor(source.key),
      );
      var code = 0;
      var comments = 0;
      var first = 0;
      for (var index = 0; index < facts.length; index++) {
        final _LineFacts fact = facts[index];
        if (fact.code.trim().isNotEmpty) code++;
        if (fact.comment.trim().isNotEmpty) {
          comments++;
          first = first == 0 ? index + 1 : first;
        }
      }
      if (code + comments >= 20) {
        files.add((
          path: source.key,
          code: code,
          comments: comments,
          first: first,
        ));
      }
    }
    if (files.length < 5) return;
    final List<double> ratios =
        files
            .map((file) => file.comments / (file.code + file.comments))
            .toList()
          ..sort();
    final double median = ratios[ratios.length ~/ 2];
    for (final file in files) {
      if (file.comments < 8 || file.code < 5) continue;
      final double ratio = file.comments / (file.code + file.comments);
      final double baseline = median < 0.04 ? 0.04 : median;
      if (ratio < 0.10 || ratio < baseline * 2.5) continue;
      yield report(
        context,
        path: file.path,
        line: file.first,
        message:
            '${file.comments} comment lines for ${file.code} code lines '
            '(${(ratio * 100).round()}%; repository median ${(median * 100).round()}%)',
        confidence: 'medium',
      );
    }
  }
}

/// Reports explicit diary-style sequencing in implementation comments.
final class NarratingImplementationCommentRule extends SelfContainedRule {
  /// Creates the implementation-comment narration rule.
  NarratingImplementationCommentRule()
    : super(generatedCodeRiskMetadata['narrating-implementation-comment']!);

  static final RegExp _narration = RegExp(
    r'^\s*(?:(?:first|next|now|then|finally),?\s+(?:we|i)(?:\s+will|\s+need\s+to|\s+can|\s+should)?|(?:we|i)\s+(?:will|need\s+to|are\s+going\s+to)\s+(?:first|next|now|then))\b',
    caseSensitive: false,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (_excludedCommentPath(source.key)) continue;
      final List<_LineFacts> facts = _scanLines(
        source.key,
        context.linesFor(source.key),
      );
      for (var index = 0; index < facts.length; index++) {
        final _LineFacts fact = facts[index];
        if (!fact.documentation && _narration.hasMatch(fact.comment)) {
          yield report(
            context,
            path: source.key,
            line: index + 1,
            message: 'comment narrates the implementation sequence',
            confidence: 'high',
          );
        }
      }
    }
  }
}

/// Reports narrow comments that lexically repeat the adjacent statement.
final class TrivialCommentRestatementRule extends SelfContainedRule {
  /// Creates the adjacent code-restatement rule.
  TrivialCommentRestatementRule()
    : super(generatedCodeRiskMetadata['trivial-comment-restatement']!);

  static final RegExp _commentShape = RegExp(
    r'^\s*(return|returns|increment|increments|decrement|decrements|set|sets|assign|assigns|call|calls|invoke|invokes)\s+(?:the\s+)?([A-Za-z_]\w*)[.!]?\s*$',
    caseSensitive: false,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (_excludedCommentPath(source.key)) continue;
      final List<_LineFacts> facts = _scanLines(
        source.key,
        context.linesFor(source.key),
      );
      for (var index = 0; index < facts.length - 1; index++) {
        final _LineFacts fact = facts[index];
        if (fact.documentation || fact.code.trim().isNotEmpty) continue;
        final RegExpMatch? match = _commentShape.firstMatch(fact.comment);
        if (match == null) continue;
        var next = index + 1;
        while (next < facts.length && facts[next].code.trim().isEmpty) {
          if (facts[next].comment.trim().isNotEmpty) break;
          next++;
        }
        if (next >= facts.length) continue;
        final String code = facts[next].code.trim();
        final String verb = match.group(1)!.toLowerCase();
        final String name = match.group(2)!;
        if (!_restates(verb, name, code)) continue;
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message:
              'comment restates `${code.length > 80 ? '${code.substring(0, 77)}...' : code}`',
          confidence: 'high',
        );
      }
    }
  }

  static bool _restates(String verb, String name, String code) {
    final String escaped = RegExp.escape(name);
    if (verb.startsWith('return')) {
      return RegExp('^return\\s+$escaped\\s*[;)]?').hasMatch(code);
    }
    if (verb.startsWith('increment')) {
      return RegExp(
        '^(?:\\+\\+$escaped|$escaped\\+\\+)\\s*;?\$',
      ).hasMatch(code);
    }
    if (verb.startsWith('decrement')) {
      return RegExp('^(?:--$escaped|$escaped--)\\s*;?\$').hasMatch(code);
    }
    if (verb.startsWith('set') || verb.startsWith('assign')) {
      return RegExp('^(?:[A-Za-z_]+\\.)?$escaped\\s*=').hasMatch(code);
    }
    return RegExp(
      '^(?:await\\s+)?(?:[A-Za-z_]+\\.)?$escaped\\s*\\(',
    ).hasMatch(code);
  }
}

/// Reports a deliberately narrow Dart pass-through class shape.
final class SingleMethodDelegatingClassRule extends SelfContainedRule {
  /// Creates the narrow Dart delegation-wrapper rule.
  SingleMethodDelegatingClassRule()
    : super(generatedCodeRiskMetadata['single-method-delegating-class']!);

  static final RegExp _candidate = RegExp(
    r'class\s+([A-Za-z_]\w*)\s*\{\s*(?:final\s+)?([A-Za-z_]\w*(?:<[^;{}]+>)?)\s+([A-Za-z_]\w*)\s*;\s*\1\s*\(\s*this\.\3\s*\)\s*;\s*(?:Future(?:<[^>{}]+>)?|[A-Za-z_]\w*(?:<[^>{}]+>)?|void)\s+([A-Za-z_]\w*)\s*\(([^{};]*)\)\s*(?:async\s*)?=>\s*(?:await\s+)?\3\.\4\s*\(([^{};]*)\)\s*;\s*\}',
    multiLine: true,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.dart') || _excludedCommentPath(source.key)) {
        continue;
      }
      for (final RegExpMatch match in _candidate.allMatches(source.value)) {
        final List<String> parameters = _parameterNames(match.group(5)!);
        final List<String> arguments = _arguments(match.group(6)!);
        if (parameters.isEmpty || !_sameItems(parameters, arguments)) continue;
        final int line =
            '\n'.allMatches(source.value.substring(0, match.start)).length + 1;
        yield report(
          context,
          path: source.key,
          line: line,
          message:
              '`${match.group(1)}` only forwards `${match.group(4)}` to `${match.group(3)}` with unchanged arguments',
          confidence: 'high',
        );
      }
    }
  }

  static List<String> _parameterNames(String source) => source
      .split(',')
      .map((String parameter) => parameter.trim().split(RegExp(r'\s+')).last)
      .where((String name) => RegExp(r'^[A-Za-z_]\w*$').hasMatch(name))
      .toList(growable: false);

  static List<String> _arguments(String source) => source
      .split(',')
      .map((String argument) => argument.trim())
      .where((String argument) => argument.isNotEmpty)
      .toList(growable: false);

  static bool _sameItems(List<String> left, List<String> right) =>
      left.length == right.length &&
      List<bool>.generate(
        left.length,
        (int index) => left[index] == right[index],
      ).every((bool same) => same);
}

final class _SchemaLiteral {
  const _SchemaLiteral(this.path, this.line, this.keys);

  final String path;
  final int line;
  final Set<String> keys;
}

/// Reports identical substantial string-key literals owned by different files.
final class ParallelSchemaDefinitionRule extends SelfContainedRule {
  /// Creates the repeated cross-file schema rule.
  ParallelSchemaDefinitionRule()
    : super(generatedCodeRiskMetadata['parallel-schema-definition']!);

  static final RegExp _literal = RegExp(r'\{([^{}]{0,4000})\}', dotAll: true);
  static final RegExp _key = RegExp(
    r'''["']([A-Za-z_][A-Za-z0-9_-]*)["']\s*:''',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, List<_SchemaLiteral>> bySignature = {};
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (_excludedSchemaPath(source.key)) continue;
      for (final RegExpMatch literal in _literal.allMatches(source.value)) {
        final Set<String> keys = _key
            .allMatches(literal.group(1)!)
            .map((RegExpMatch match) => match.group(1)!)
            .toSet();
        if (keys.length < 5) continue;
        final List<String> sorted = keys.toList()..sort();
        final String signature = sorted.join('\u0000');
        final int line =
            '\n'.allMatches(source.value.substring(0, literal.start)).length +
            1;
        bySignature
            .putIfAbsent(signature, () => <_SchemaLiteral>[])
            .add(_SchemaLiteral(source.key, line, keys));
      }
    }
    for (final List<_SchemaLiteral> matches in bySignature.values) {
      final Map<String, _SchemaLiteral> byPath = {
        for (final _SchemaLiteral match in matches) match.path: match,
      };
      if (byPath.length < 2) continue;
      final List<_SchemaLiteral> distinct = byPath.values.toList()
        ..sort(
          (_SchemaLiteral a, _SchemaLiteral b) => a.path.compareTo(b.path),
        );
      final _SchemaLiteral primary = distinct.first;
      yield report(
        context,
        path: primary.path,
        line: primary.line,
        message:
            '${primary.keys.length}-key contract is repeated in ${distinct.length} files',
        confidence: 'medium',
        relatedFiles: distinct
            .skip(1)
            .map((item) => '${item.path}:${item.line}')
            .toList(),
      );
    }
  }

  static bool _excludedSchemaPath(String path) {
    final String lower = path.toLowerCase();
    return _testPath.hasMatch(lower) ||
        _generatedPath.hasMatch(lower) ||
        RegExp(
          r'(^|/)(?:assets|i18n|l10n|locale|locales)(?:/|$)',
        ).hasMatch(lower) ||
        RegExp(
          r'(?:^|/)(?:package(?:-lock)?|pubspec|composer|cargo)\.(?:json|yaml|yml|toml)$',
        ).hasMatch(lower);
  }
}
