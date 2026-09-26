// Conservative cross-language clean-code evidence belongs here so language packs do not drift.

import 'package:path/path.dart' as path;

import '../../core/models.dart';
import '../../core/rule.dart';
import 'generic_rules.dart';

const Set<String> _sourceExtensions = <String>{
  '.c',
  '.cc',
  '.cpp',
  '.cs',
  '.dart',
  '.go',
  '.h',
  '.hpp',
  '.java',
  '.js',
  '.jsx',
  '.kt',
  '.kts',
  '.lua',
  '.m',
  '.mm',
  '.mojo',
  '.nim',
  '.php',
  '.py',
  '.rs',
  '.swift',
  '.ts',
  '.tsx',
  '.wren',
};

final Map<String, RuleMetadata> cleanCodeRuleMetadata = <String, RuleMetadata>{
  'public-mutable-state': _metadata(
    'public-mutable-state',
    'Encapsulate public mutable state',
    'Publicly writable state lets callers bypass invariants and couples them to representation details.',
    'Make the field private and expose behavior or a deliberately constrained immutable view.',
    maturity: RuleSemanticMaturity.token,
  ),
  'commented-out-code': _metadata(
    'commented-out-code',
    'Remove commented-out code',
    'Disabled source in comments rots, obscures current behavior, and duplicates version-control history.',
    'Delete the disabled code and recover it from version control if it is needed later.',
    maturity: RuleSemanticMaturity.token,
  ),
  'placeholder-identifier': _metadata(
    'placeholder-identifier',
    'Replace a placeholder identifier',
    'A placeholder name hides the role of a declaration once it escapes a tiny local scope.',
    'Rename the declaration for the domain concept or responsibility it represents.',
    maturity: RuleSemanticMaturity.token,
  ),
  'mixed-boundary-responsibility': _metadata(
    'mixed-boundary-responsibility',
    'Split mixed boundary responsibilities',
    'One function coordinates several unrelated external boundaries, increasing coupling and change surface.',
    'Keep orchestration explicit, or move independently changing boundary work behind focused operations.',
    maturity: RuleSemanticMaturity.project,
  ),
  'repeated-policy-literal': _metadata(
    'repeated-policy-literal',
    'Name a repeated policy literal',
    'A repeated threshold, duration, or capacity literal can drift because its purpose is not named.',
    'Define one purpose-named constant near the behavior that owns this policy.',
    maturity: RuleSemanticMaturity.project,
  ),
  'inconsistent-peer-file-naming': _metadata(
    'inconsistent-peer-file-naming',
    'Follow the local file naming convention',
    'A lone naming-style outlier makes related files harder to scan and discover.',
    'Rename the file to the dominant convention used by its peers.',
    maturity: RuleSemanticMaturity.project,
  ),
  'changed-public-api-without-test': _metadata(
    'changed-public-api-without-test',
    'Cover a changed public API',
    'A changed public declaration without a related changed test has no review-visible regression evidence.',
    'Add or update a behavior-focused test for the changed public contract.',
    maturity: RuleSemanticMaturity.project,
    limitations: const <String>[
      'Runs only with changed-base evidence and reports only when no changed test path shares the production file concept.',
      'Tests in external repositories and unchanged broad integration suites cannot be resolved.',
    ],
  ),
  'changed-complexity-regression': _metadata(
    'changed-complexity-regression',
    'Reduce changed-code complexity growth',
    'A changed function added several decision points and crossed a high-complexity threshold.',
    'Split independent decisions or simplify the changed control flow before it becomes harder to test.',
    maturity: RuleSemanticMaturity.project,
    limitations: const <String>[
      'Runs only with changed-base source snapshots and compares brace-delimited named functions.',
      'Macro expansion, generated functions, overload identity, and parser recovery are not resolved.',
    ],
  ),
};

RuleMetadata _metadata(
  String id,
  String title,
  String why,
  String suggestion, {
  required RuleSemanticMaturity maturity,
  List<String> limitations = const <String>[],
}) => RuleMetadata(
  id: id,
  version: 1,
  defaultSeverity: RuleSeverity.info,
  group: 'maintainability',
  title: title,
  why: why,
  suggestion: suggestion,
  semanticMaturity: maturity,
  taxonomy: const <FindingTaxonomy>{FindingTaxonomy.maintainability},
  limitations: limitations,
);

abstract base class _CleanCodeRule extends SelfContainedRule {
  _CleanCodeRule(String id) : super(cleanCodeRuleMetadata[id]!);

  Finding finding(
    RuleContext context,
    String path,
    int line,
    String message, {
    String confidence = 'high',
    List<String> relatedFiles = const <String>[],
  }) => report(
    context,
    path: path,
    line: line,
    message: message,
    confidence: confidence,
    relatedFiles: relatedFiles,
  );
}

final class PublicMutableStateRule extends _CleanCodeRule {
  PublicMutableStateRule() : super('public-mutable-state');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isSource(entry.key) || _isTest(entry.key)) continue;
      final List<String> lines = maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      );
      var depth = 0;
      int? classDepth;
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        if (RegExp(r'\b(?:class|struct)\s+[A-Za-z_$]\w*').hasMatch(line)) {
          classDepth = depth + '{'.allMatches(line).length;
        }
        final bool directMember = classDepth != null && depth == classDepth;
        final RegExpMatch? explicit = RegExp(
          r'^\s*public\s+(?!(?:static\s+)?(?:final|readonly|const)\b)(?:static\s+)?(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)+(\w+)\s*(?:=|;)',
        ).firstMatch(line);
        final RegExpMatch? dart = directMember && entry.key.endsWith('.dart')
            ? RegExp(
                r'^\s*(?!(?:final|const|late\s+final)\b)(?:late\s+)?(?:var|[A-Za-z_$][\w$<>,?\[\].]*)\s+([A-Za-z$][\w$]*)\s*(?:=|;)',
              ).firstMatch(line)
            : null;
        final RegExpMatch? script =
            directMember &&
                const <String>{
                  '.js',
                  '.jsx',
                  '.ts',
                  '.tsx',
                }.contains(path.extension(entry.key).toLowerCase())
            ? RegExp(
                r'^\s*(?!(?:private|protected|readonly|static|declare|#)\b)(?:public\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=;]+)?(?:=|;)',
              ).firstMatch(line)
            : null;
        final String? name =
            explicit?.group(1) ?? dart?.group(1) ?? script?.group(1);
        if (name != null && !name.startsWith('_')) {
          yield finding(
            context,
            entry.key,
            index + 1,
            'public mutable field `$name` exposes writable state',
          );
        }
        depth += '{'.allMatches(line).length - '}'.allMatches(line).length;
        if (classDepth != null && depth < classDepth) classDepth = null;
      }
    }
  }
}

final class CommentedOutCodeRule extends _CleanCodeRule {
  CommentedOutCodeRule() : super('commented-out-code');

  static final RegExp _code = RegExp(
    r'^(?:\s*(?:public|private|protected|internal|static|final|const|var|let|def|class|interface|return|throw|if\s*\(|for\s*\(|while\s*\(|[A-Za-z_$]\w*\s*[.(\[]).*(?:[;{}]|=>)\s*)$',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isSource(entry.key) || _isTest(entry.key)) continue;
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? comment = RegExp(
          r'^\s*(?://|#)\s?(.*)$',
        ).firstMatch(lines[index]);
        if (comment == null) continue;
        final String body = comment.group(1)!.trim();
        if (body.length >= 8 &&
            _code.hasMatch(body) &&
            !_looksLikeDirective(body)) {
          yield finding(
            context,
            entry.key,
            index + 1,
            'comment contains disabled source code',
          );
        }
      }
    }
  }
}

final class PlaceholderIdentifierRule extends _CleanCodeRule {
  PlaceholderIdentifierRule() : super('placeholder-identifier');

  static const Set<String> _names = <String>{
    'asdf',
    'bar',
    'baz',
    'dummy',
    'foo',
    'obj',
    'stuff',
    'thing',
    'whatever',
  };

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isSource(entry.key) || _isTest(entry.key)) continue;
      final List<String> lines = maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      );
      final String source = lines.join('\n');
      for (var index = 0; index < lines.length; index++) {
        for (final RegExpMatch match in RegExp(
          r'\b(?:export\s+|public\s+)?(?:class|interface|enum|struct|def|function|fn|proc|func|void|var|let|const|final|[A-Z][\w$<>,?\[\].]*)\s+([A-Za-z_$][\w$]*)',
        ).allMatches(lines[index])) {
          final String name = match.group(1)!;
          final String normalized = name.toLowerCase().replaceAll(
            RegExp(r'\d+$'),
            '',
          );
          if (!_names.contains(normalized)) continue;
          final bool exposed = RegExp(
            r'\b(?:export|public)\b',
          ).hasMatch(lines[index]);
          final int uses = RegExp(
            '\\b${RegExp.escape(name)}\\b',
          ).allMatches(source).length;
          if (exposed || uses >= 3) {
            yield finding(
              context,
              entry.key,
              index + 1,
              '`$name` is a placeholder name used beyond a tiny local scope',
            );
          }
        }
      }
    }
  }
}

final class MixedBoundaryResponsibilityRule extends _CleanCodeRule {
  MixedBoundaryResponsibilityRule() : super('mixed-boundary-responsibility');

  static const Map<String, String> _boundaries = <String, String>{
    'persistence':
        r'\b(?:insert|update|delete|save|repository|database|query|executeSql)\b',
    'network': r'\b(?:http|client\.(?:get|post|put|send)|fetch|request)\b',
    'filesystem':
        r'\b(?:File|Directory|readAs|writeAs|openSync|readFile|writeFile)\b',
    'process': r'\b(?:Process\.(?:run|start)|exec|spawn|subprocess)\b',
    'telemetry': r'\b(?:analytics|telemetry|metrics|track|logger?\.)\b',
    'navigation': r'\b(?:Navigator|router\.|redirect|navigate)\b',
  };

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isSource(entry.key) || _isTest(entry.key)) continue;
      for (final _FunctionBlock function in _functionBlocks(entry.value)) {
        if (function.lines < 8 ||
            RegExp(
              r'\b(?:main|bootstrap|migrate|transaction)\b',
              caseSensitive: false,
            ).hasMatch(function.name)) {
          continue;
        }
        final List<String> boundaries = <String>[
          for (final MapEntry<String, String> boundary in _boundaries.entries)
            if (RegExp(
              boundary.value,
              caseSensitive: false,
            ).hasMatch(function.body))
              boundary.key,
        ];
        if (boundaries.length >= 3) {
          yield finding(
            context,
            entry.key,
            function.line,
            '${function.name} directly coordinates ${boundaries.join(', ')} boundaries',
            confidence: 'medium',
          );
        }
      }
    }
  }
}

final class RepeatedPolicyLiteralRule extends _CleanCodeRule {
  RepeatedPolicyLiteralRule() : super('repeated-policy-literal');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, List<({String path, int line})>> uses =
        <String, List<({String path, int line})>>{};
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isSource(entry.key) || _isTest(entry.key)) continue;
      final List<String> lines = maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      );
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        if (!RegExp(
          r'(?:[<>]=?|==|!=)\s*\d|\b(?:Duration|timeout|retry|limit|capacity|max|min|threshold)\b',
          caseSensitive: false,
        ).hasMatch(line)) {
          continue;
        }
        for (final RegExpMatch match in RegExp(
          r'(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])',
        ).allMatches(line)) {
          final String literal = match.group(0)!;
          if (const <String>{
            '-1',
            '0',
            '1',
            '2',
            '10',
            '100',
          }.contains(literal)) {
            continue;
          }
          uses.putIfAbsent(literal, () => <({String path, int line})>[]).add((
            path: entry.key,
            line: index + 1,
          ));
        }
      }
    }
    for (final MapEntry<String, List<({String path, int line})>> entry
        in uses.entries) {
      final Set<String> paths = entry.value.map((use) => use.path).toSet();
      if (entry.value.length < 3 && paths.length < 2) continue;
      final first = entry.value.first;
      yield finding(
        context,
        first.path,
        first.line,
        'policy literal `${entry.key}` appears ${entry.value.length} times without a shared name',
        confidence: 'medium',
        relatedFiles:
            paths.where((candidate) => candidate != first.path).toList()
              ..sort(),
      );
    }
  }
}

final class InconsistentPeerFileNamingRule extends _CleanCodeRule {
  InconsistentPeerFileNamingRule() : super('inconsistent-peer-file-naming');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, List<String>> byDirectory = <String, List<String>>{};
    for (final String sourcePath in context.sources.keys.where(_isSource)) {
      byDirectory
          .putIfAbsent(path.posix.dirname(sourcePath), () => <String>[])
          .add(sourcePath);
    }
    for (final List<String> peers in byDirectory.values) {
      if (peers.length < 6) continue;
      final Map<String, List<String>> styles = <String, List<String>>{};
      for (final String peer in peers) {
        styles
            .putIfAbsent(
              _fileStyle(path.posix.basenameWithoutExtension(peer)),
              () => <String>[],
            )
            .add(peer);
      }
      final List<MapEntry<String, List<String>>> ordered =
          styles.entries.toList()..sort(
            (left, right) => right.value.length.compareTo(left.value.length),
          );
      if (ordered.first.value.length < 5) continue;
      for (final MapEntry<String, List<String>> style in ordered.skip(1)) {
        if (style.value.length != 1) continue;
        yield finding(
          context,
          style.value.single,
          1,
          'file name is the lone `${style.key}` outlier among `${ordered.first.key}` peers',
          confidence: 'high',
          relatedFiles: ordered.first.value.take(3).toList(),
        );
      }
    }
  }
}

final class ChangedPublicApiWithoutTestRule extends _CleanCodeRule {
  ChangedPublicApiWithoutTestRule() : super('changed-public-api-without-test');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (context.config.changedBase.isEmpty || context.changedPaths.isEmpty) {
      return;
    }
    final List<String> changedTests = context.changedPaths
        .where(_isTest)
        .toList();
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!context.changedPaths.contains(entry.key) || _isTest(entry.key)) {
        continue;
      }
      final List<String> lines = maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      );
      final int index = lines.indexWhere(
        (line) => RegExp(
          r'^\s*(?:export\s+|public\s+|abstract\s+interface\s+class\s+|class\s+[A-Z])',
        ).hasMatch(line),
      );
      if (index < 0) continue;
      final Set<String> concepts = _pathConcepts(entry.key);
      final bool relatedTest = changedTests.any(
        (test) => _pathConcepts(test).intersection(concepts).isNotEmpty,
      );
      if (!relatedTest) {
        yield finding(
          context,
          entry.key,
          index + 1,
          'changed public API has no concept-related changed test',
          confidence: 'medium',
        );
      }
    }
  }
}

final class ChangedComplexityRegressionRule extends _CleanCodeRule {
  ChangedComplexityRegressionRule() : super('changed-complexity-regression');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (context.config.changedBase.isEmpty || context.baseSources.isEmpty) {
      return;
    }
    for (final MapEntry<String, String> entry in context.sources.entries) {
      final String? before = context.baseSources[entry.key];
      if (before == null) continue;
      final Map<String, _FunctionBlock> oldFunctions = <String, _FunctionBlock>{
        for (final function in _functionBlocks(before)) function.name: function,
      };
      for (final _FunctionBlock current in _functionBlocks(entry.value)) {
        final _FunctionBlock? old = oldFunctions[current.name];
        if (old == null) continue;
        final int currentComplexity = _complexity(current.body);
        final int oldComplexity = _complexity(old.body);
        if (currentComplexity >= 10 && currentComplexity - oldComplexity >= 4) {
          yield finding(
            context,
            entry.key,
            current.line,
            '${current.name} complexity increased from $oldComplexity to $currentComplexity',
            confidence: 'high',
          );
        }
      }
    }
  }
}

bool _isSource(String sourcePath) =>
    _sourceExtensions.contains(path.extension(sourcePath).toLowerCase());
bool _isTest(String sourcePath) => RegExp(
  r'(^|/)(?:test|tests|spec|specs|__tests__)(/|$)|(?:_test|\.test|\.spec)\.',
  caseSensitive: false,
).hasMatch(sourcePath.replaceAll('\\', '/'));
bool _looksLikeDirective(String body) => RegExp(
  r'^(?:include|define|pragma|region|ifn?def)\b',
  caseSensitive: false,
).hasMatch(body);

String _fileStyle(String name) {
  if (name.contains('_')) return 'snake_case';
  if (name.contains('-')) return 'kebab-case';
  if (RegExp(r'^[A-Z]').hasMatch(name)) return 'PascalCase';
  if (RegExp(r'[A-Z]').hasMatch(name)) return 'camelCase';
  return 'lowercase';
}

Set<String> _pathConcepts(String sourcePath) {
  const Set<String> ignored = <String>{
    'src',
    'lib',
    'test',
    'tests',
    'spec',
    'index',
    'main',
  };
  return path.posix
      .basenameWithoutExtension(sourcePath)
      .toLowerCase()
      .split(RegExp(r'[_\-.]|(?=[A-Z])'))
      .where((part) => part.length >= 3 && !ignored.contains(part))
      .toSet();
}

final class _FunctionBlock {
  const _FunctionBlock(this.name, this.body, this.line, this.lines);
  final String name;
  final String body;
  final int line;
  final int lines;
}

List<_FunctionBlock> _functionBlocks(String source) {
  final List<String> lines = maskGenericRuleStrings(
    source.split('\n'),
    sourcePath: '',
  );
  final List<_FunctionBlock> result = <_FunctionBlock>[];
  final RegExp declaration = RegExp(
    r'^\s*(?:(?:public|private|protected|internal|static|final|async|export)\s+)*(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:async\s*)?(?:=>|\{)',
  );
  for (var index = 0; index < lines.length; index++) {
    final RegExpMatch? match = declaration.firstMatch(lines[index]);
    if (match == null || lines[index].contains('=>')) continue;
    var depth = 0;
    var seenBrace = false;
    final StringBuffer body = StringBuffer();
    var end = index;
    for (; end < lines.length; end++) {
      final String line = lines[end];
      body.writeln(line);
      final int opens = '{'.allMatches(line).length;
      final int closes = '}'.allMatches(line).length;
      if (opens > 0) seenBrace = true;
      depth += opens - closes;
      if (seenBrace && depth <= 0) break;
    }
    if (seenBrace) {
      result.add(
        _FunctionBlock(
          match.group(1)!,
          body.toString(),
          index + 1,
          end - index + 1,
        ),
      );
    }
    index = end;
  }
  return result;
}

int _complexity(String body) =>
    1 +
    RegExp(
      r'\b(?:if|for|while|case|catch)\b|&&|\|\||\?',
    ).allMatches(body).length;
