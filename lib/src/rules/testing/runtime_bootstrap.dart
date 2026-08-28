// Repeatedly starting a compiler or language runtime in process tests turns one test run into many avoidable bootstrap cycles.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports the same runtime or build entrypoint launched repeatedly from tests.
final class TestRepeatedRuntimeBootstrapRule extends SelfContainedRule {
  /// Creates the project-level test bootstrap check.
  const TestRepeatedRuntimeBootstrapRule()
    : super(
        const RuleMetadata(
          id: 'test-repeated-runtime-bootstrap',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Reuse compiled test executables',
          why:
              'Each test process can repeat runtime startup, dependency loading, or compilation for the same entrypoint.',
          suggestion:
              'Compile or prepare the target once in shared test setup, then reuse that executable or artifact.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.performance},
          limitations: <String>[
            'Only literal process commands in selected test sources are checked.',
            'Tests must be included in analysis with --include-tests or --all.',
            'A repeated launch is evidence of bootstrap cost, not proof that every tool recompiles on every invocation.',
          ],
        ),
      );

  static final RegExp _processCall = RegExp(
    r'\b(?:Process\.(?:run|start)|subprocess\.(?:run|Popen|call)|child_process\.(?:spawn|execFile)|spawn|execFile|execa)\s*\(',
  );
  static final RegExp _quoted = RegExp(r'''["']([^"']+)["']''');
  static final RegExp _direct = RegExp(
    r'''\b(dart\s+run|cargo\s+run|go\s+run|dotnet\s+run|mvnw?|gradlew?)\s+([^\s"']+)?''',
    caseSensitive: false,
  );
  static const Set<String> _tools = <String>{
    'dart',
    'cargo',
    'go',
    'dotnet',
    'mvn',
    'mvnw',
    'gradle',
    'gradlew',
  };

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, List<_BootstrapOccurrence>> grouped =
        <String, List<_BootstrapOccurrence>>{};
    final Set<String> seenLocations = <String>{};
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_isTestPath(entry.key)) continue;
      for (final RegExpMatch call in _processCall.allMatches(entry.value)) {
        final int end = (call.start + 800).clamp(0, entry.value.length);
        final String window = entry.value.substring(call.start, end);
        final List<String> tokens = _quoted
            .allMatches(window)
            .map((RegExpMatch match) => match.group(1)!)
            .take(16)
            .toList(growable: false);
        final _BootstrapTarget? target = _targetFromTokens(window, tokens);
        if (target != null) {
          _add(
            grouped,
            seenLocations,
            target,
            entry.key,
            _lineAt(entry.value, call.start),
          );
        }
      }
      final List<String> lines = entry.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String trimmed = lines[index].trimLeft();
        if (trimmed.startsWith('//') ||
            trimmed.startsWith('#') ||
            trimmed.startsWith('*')) {
          continue;
        }
        for (final RegExpMatch command in _direct.allMatches(lines[index])) {
          final String phrase = command.group(1)!.toLowerCase();
          final List<String> parts = phrase.split(RegExp(r'\s+'));
          final String tool = parts.first;
          var operation = parts.length > 1 ? parts[1] : '';
          final String argument = command.group(2) ?? '';
          var arguments = <String>[argument];
          if (parts.length == 1 &&
              const <String>{
                'mvn',
                'mvnw',
                'gradle',
                'gradlew',
              }.contains(tool)) {
            operation = argument;
            arguments = const <String>[];
          }
          final _BootstrapTarget target = _BootstrapTarget(
            tool,
            _normalizeTarget(tool, operation, arguments),
          );
          _add(grouped, seenLocations, target, entry.key, index + 1);
        }
      }
    }

    final List<String> keys = grouped.keys.toList()..sort();
    for (final String key in keys) {
      final List<_BootstrapOccurrence> occurrences = grouped[key]!
        ..sort(
          (_BootstrapOccurrence left, _BootstrapOccurrence right) =>
              left.path.compareTo(right.path) != 0
              ? left.path.compareTo(right.path)
              : left.line.compareTo(right.line),
        );
      if (occurrences.length < 3) continue;
      final _BootstrapOccurrence reported = occurrences[2];
      yield report(
        context,
        path: reported.path,
        line: reported.line,
        message:
            '`${reported.tool}` bootstraps `${reported.target}` ${occurrences.length} times in tests',
        confidence: 'medium',
        relatedFiles: <String>[
          for (final _BootstrapOccurrence occurrence in occurrences.take(5))
            '${occurrence.path}:${occurrence.line}',
        ],
      );
    }
  }
}

_BootstrapTarget? _targetFromTokens(String window, List<String> tokens) {
  final bool resolvedDart = window.contains('Platform.resolvedExecutable');
  if (resolvedDart) {
    final String target = tokens.firstWhere(
      (String token) => token.endsWith('.dart'),
      orElse: () => '',
    );
    return target.isEmpty ? null : _BootstrapTarget('dart', target);
  }

  var toolIndex = -1;
  for (var index = 0; index < tokens.length; index++) {
    final String candidate = tokens[index]
        .split(RegExp(r'[/\\]'))
        .last
        .toLowerCase();
    if (TestRepeatedRuntimeBootstrapRule._tools.contains(candidate)) {
      toolIndex = index;
      break;
    }
  }
  if (toolIndex == -1) return null;
  final String tool = tokens[toolIndex]
      .split(RegExp(r'[/\\]'))
      .last
      .toLowerCase();
  final List<String> arguments = tokens.skip(toolIndex + 1).toList();
  final String operation = arguments.isNotEmpty ? arguments.removeAt(0) : '';
  if (const <String>{'dart', 'cargo', 'go', 'dotnet'}.contains(tool) &&
      operation != 'run') {
    return null;
  }
  return _BootstrapTarget(tool, _normalizeTarget(tool, operation, arguments));
}

String _normalizeTarget(String tool, String operation, List<String> arguments) {
  if (tool == 'cargo') {
    final int bin = arguments.indexOf('--bin');
    return bin >= 0 && bin + 1 < arguments.length
        ? arguments[bin + 1]
        : 'workspace';
  }
  if (tool == 'dotnet') {
    final int project = arguments.indexOf('--project');
    return project >= 0 && project + 1 < arguments.length
        ? arguments[project + 1]
        : 'project';
  }
  if (tool == 'mvn' ||
      tool == 'mvnw' ||
      tool == 'gradle' ||
      tool == 'gradlew') {
    return operation.isEmpty ? 'default task' : operation;
  }
  final String target = arguments.firstWhere(
    (String argument) => argument.isNotEmpty && !argument.startsWith('-'),
    orElse: () => '',
  );
  return target.isEmpty ? 'default target' : target;
}

void _add(
  Map<String, List<_BootstrapOccurrence>> grouped,
  Set<String> seenLocations,
  _BootstrapTarget target,
  String path,
  int line,
) {
  final String location = '$path:$line:${target.tool}:${target.target}';
  if (!seenLocations.add(location)) return;
  final String key = '${target.tool}:${target.target}';
  grouped
      .putIfAbsent(key, () => <_BootstrapOccurrence>[])
      .add(_BootstrapOccurrence(path, line, target.tool, target.target));
}

bool _isTestPath(String path) {
  final String normalized = path.replaceAll(r'\', '/').toLowerCase();
  final String name = normalized.split('/').last;
  return RegExp(
        r'(^|/)(?:test|tests|spec|specs|__tests__)(/|$)',
      ).hasMatch(normalized) ||
      RegExp(
        r'(?:_test\.dart|\.test\.[a-z]+|\.spec\.[a-z]+|^test_.*\.py$)',
      ).hasMatch(name);
}

int _lineAt(String source, int offset) =>
    1 + '\n'.allMatches(source.substring(0, offset)).length;

final class _BootstrapTarget {
  const _BootstrapTarget(this.tool, this.target);

  final String tool;
  final String target;
}

final class _BootstrapOccurrence {
  const _BootstrapOccurrence(this.path, this.line, this.tool, this.target);

  final String path;
  final int line;
  final String tool;
  final String target;
}
