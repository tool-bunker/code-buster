// Third-party and built-in checks share these execution contracts, reporting helpers, and reusable rule base classes.

import '../graph/graph.dart';
import 'models.dart';

/// Immutable inputs made available to an executable Code Buster rule.
///
/// Language plugins may place their parse-once representation in
/// [languageAnalysis]. Rules must treat all context values as read-only.
final class RuleContext {
  const RuleContext({
    required this.config,
    required this.sources,
    required this.language,
    this.graph,
    this.sourceLines = const <String, List<String>>{},
    this.languageAnalysis,
  });

  final AnalysisConfig config;

  final Map<String, String> sources;

  final Map<String, List<String>> sourceLines;

  final String language;

  final DependencyGraph? graph;

  final Object? languageAnalysis;

  List<String> linesFor(String path) =>
      sourceLines[path] ?? sources[path]!.split('\n');

  T requireLanguageAnalysis<T extends Object>() {
    final Object? analysis = languageAnalysis;
    if (analysis is T) {
      return analysis;
    }
    throw StateError(
      'Rule for $language requires $T, but received ${analysis.runtimeType}',
    );
  }

  Finding report({
    required RuleMetadata metadata,
    required String path,
    required int line,
    required String message,
    int endLine = 0,
    String confidence = '',
    List<String> relatedFiles = const <String>[],
    String snippet = '',
    List<CodeFlowStep> codeFlow = const <CodeFlowStep>[],
  }) => Finding(
    code: metadata.id,
    severity: config.severityOverrides[metadata.id] ?? metadata.defaultSeverity,
    path: path,
    line: line,
    endLine: endLine,
    message: message,
    confidence: confidence,
    why: metadata.why,
    suggestion: metadata.suggestion,
    relatedFiles: relatedFiles,
    snippet: snippet,
    codeFlow: codeFlow,
  );
}

/// Blanks C-family preprocessor directives and branches that are provably
/// inactive while preserving source line numbers.
List<String> maskDefinitelyInactivePreprocessorBranches(List<String> lines) {
  final List<String> result = <String>[];
  final List<bool> parentDisabled = <bool>[];
  var disabled = false;

  for (final String line in lines) {
    final RegExpMatch? directive = _preprocessorDirective.firstMatch(line);
    if (directive == null) {
      result.add(disabled ? '' : line);
      continue;
    }

    final String name = directive.group(1)!;
    switch (name) {
      case 'if':
        parentDisabled.add(disabled);
        disabled =
            disabled ||
            _falsePreprocessorExpression.hasMatch(directive.group(2)!);
      case 'ifdef':
      case 'ifndef':
        parentDisabled.add(disabled);
      case 'elif':
        if (parentDisabled.isNotEmpty) {
          disabled =
              parentDisabled.last ||
              _falsePreprocessorExpression.hasMatch(directive.group(2)!);
        }
      case 'else':
        if (parentDisabled.isNotEmpty) {
          disabled = parentDisabled.last;
        }
      case 'endif':
        if (parentDisabled.isNotEmpty) {
          disabled = parentDisabled.removeLast();
        }
    }
    result.add('');
  }

  return result;
}

final RegExp _preprocessorDirective = RegExp(
  r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$',
);
final RegExp _falsePreprocessorExpression = RegExp(
  r'^\s*(?:\(\s*)*0+[uUlL]*(?:\s*\))*\s*(?:(?://.*)|(?:/\*.*\*/\s*))?$',
);

/// Independently executable static-analysis rule.
///
/// Implementations should be deterministic and side-effect free. Filesystem,
/// process, cache, suppression, baseline, and reporting concerns belong to
/// pipeline stages around rule execution.
abstract interface class CodeBusterRule {
  RuleMetadata get metadata;

  Iterable<Finding> analyze(RuleContext context);
}

abstract class SelfContainedRule implements CodeBusterRule {
  const SelfContainedRule(this.metadata);

  @override
  final RuleMetadata metadata;

  Finding report(
    RuleContext context, {
    required String path,
    required int line,
    required String message,
    int endLine = 0,
    String confidence = '',
    List<String> relatedFiles = const <String>[],
    String snippet = '',
    List<CodeFlowStep> codeFlow = const <CodeFlowStep>[],
  }) => context.report(
    metadata: metadata,
    path: path,
    line: line,
    endLine: endLine,
    message: message,
    confidence: confidence,
    relatedFiles: relatedFiles,
    snippet: snippet,
    codeFlow: codeFlow,
  );
}

/// Declarative source-text rule for narrow, line-local patterns.
final class SourcePatternRule extends SelfContainedRule {
  SourcePatternRule({
    required RuleMetadata metadata,
    required this.pattern,
    required this.message,
    this.exclusion,
    this.confidence = 'high',
    this.includeCommentsAndStrings = false,
    this.codeFlowMessage,
    this.pathExclusion,
    this.oncePerFile = false,
  }) : super(metadata);

  final RegExp pattern;

  final RegExp? exclusion;

  final String message;

  final String confidence;

  final String? codeFlowMessage;

  final bool includeCommentsAndStrings;

  final bool Function(String path)? pathExclusion;
  final bool oncePerFile;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (metadata.languages.isNotEmpty &&
        !metadata.languages.contains(context.language)) {
      return;
    }
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (pathExclusion?.call(source.key) ?? false) continue;
      final List<String> lines = context.linesFor(source.key);
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) scanned = _maskNonCode(
          lines[index],
          inBlockComment: inBlockComment,
        );
        inBlockComment = scanned.inBlockComment;
        final String line = includeCommentsAndStrings
            ? lines[index]
            : scanned.code;
        if (pattern.hasMatch(line) && !(exclusion?.hasMatch(line) ?? false)) {
          yield report(
            context,
            path: source.key,
            line: index + 1,
            message: message,
            confidence: confidence,
            codeFlow: codeFlowMessage == null
                ? const <CodeFlowStep>[]
                : <CodeFlowStep>[
                    CodeFlowStep(
                      path: source.key,
                      line: index + 1,
                      message: codeFlowMessage!,
                    ),
                  ],
          );
          if (oncePerFile) break;
        }
      }
    }
  }
}

abstract class SemanticRule<T extends Object> extends SelfContainedRule {
  const SemanticRule(super.metadata);

  @override
  Iterable<Finding> analyze(RuleContext context) =>
      analyzeSemantic(context, context.requireLanguageAnalysis<T>());

  Iterable<Finding> analyzeSemantic(RuleContext context, T analysis);
}

({String code, bool inBlockComment}) _maskNonCode(
  String line, {
  required bool inBlockComment,
}) {
  final StringBuffer result = StringBuffer();
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
      result.write(' ');
      continue;
    }
    if (quote != null) {
      result.write(' ');
      if (escaped) {
        escaped = false;
      } else if (character == r'\') {
        escaped = true;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == '"' || character == "'" || character == '`') {
      quote = character;
      result.write(' ');
      continue;
    }
    if (character == '/' && next == '*') {
      inBlockComment = true;
      result.write(' ');
      index++;
      continue;
    }
    if (character == '/' && next == '/') break;
    result.write(character);
  }
  return (code: result.toString(), inBlockComment: inBlockComment);
}

final class RuleRegistry {
  RuleRegistry(Iterable<CodeBusterRule> rules)
    : _rules = Map<String, CodeBusterRule>.unmodifiable(_indexRules(rules));

  final Map<String, CodeBusterRule> _rules;

  Iterable<CodeBusterRule> get rules => _rules.values;

  Set<RuleAnalysisRequirement> get requirements =>
      Set<RuleAnalysisRequirement>.unmodifiable(<RuleAnalysisRequirement>{
        for (final CodeBusterRule rule in rules) ...rule.metadata.requirements,
      });

  CodeBusterRule? operator [](String id) => _rules[id];

  Iterable<RuleMetadata> get metadata =>
      rules.map((CodeBusterRule rule) => rule.metadata);

  String get versionSignature => metadata
      .map((RuleMetadata item) => '${item.id}@${item.version}')
      .join(',');

  static Map<String, CodeBusterRule> _indexRules(
    Iterable<CodeBusterRule> rules,
  ) {
    final Map<String, CodeBusterRule> indexed = <String, CodeBusterRule>{};
    for (final CodeBusterRule rule in rules) {
      final String id = rule.metadata.id;
      if (indexed.containsKey(id)) {
        throw ArgumentError.value(id, 'rules', 'duplicate rule ID');
      }
      indexed[id] = rule;
    }
    return indexed;
  }
}
