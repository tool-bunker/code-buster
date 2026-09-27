import 'package:path/path.dart' as path;

import '../../core/regexp_cache.dart';
import '../../core/rule.dart';

/// Repository change evidence shared by diff-aware quality rules.
final class SemanticDiff {
  SemanticDiff._(this.files);

  factory SemanticDiff.fromContext(RuleContext context) {
    final List<SemanticFileDiff> files = <SemanticFileDiff>[];
    for (final String sourcePath in context.changedPaths.toList()..sort()) {
      final String? after = context.sources[sourcePath];
      if (after == null ||
          !_sourceExtensions.contains(path.extension(sourcePath))) {
        continue;
      }
      files.add(
        SemanticFileDiff._(
          path: sourcePath,
          before: context.baseSources[sourcePath] ?? '',
          after: after,
        ),
      );
    }
    return SemanticDiff._(List<SemanticFileDiff>.unmodifiable(files));
  }

  final List<SemanticFileDiff> files;

  Iterable<SemanticFileDiff> get productionFiles =>
      files.where((file) => !file.isTest);
  Iterable<SemanticFileDiff> get testFiles =>
      files.where((file) => file.isTest);

  /// Whether the change is small enough for intent-oriented review heuristics.
  bool get isFocused => productionFiles.length <= 5;
}

final class SemanticFileDiff {
  SemanticFileDiff._({
    required this.path,
    required this.before,
    required this.after,
  }) : addedLines = _lineDifference(after, before),
       removedLines = _lineDifference(before, after),
       isTest = _testPath.hasMatch(path.replaceAll('\\', '/'));

  final String path;
  final String before;
  final String after;
  final List<SemanticLine> addedLines;
  final List<SemanticLine> removedLines;
  final bool isTest;

  Set<String> get concepts => path
      .split(cachedRegExp(r'[/_.-]'))
      .map((part) => part.toLowerCase())
      .where((part) => part.length >= 3 && !_ignoredConcepts.contains(part))
      .toSet();

  int get behaviorAdditions =>
      addedLines.where((line) => _behaviorLine.hasMatch(line.text)).length;

  int get declarationAdditions =>
      addedLines.where((line) => _declarationLine.hasMatch(line.text)).length;

  int get styleOnlyEdits {
    final Map<String, int> removed = <String, int>{};
    for (final SemanticLine line in removedLines) {
      final String normalized = _styleShape(line.text);
      if (normalized.isNotEmpty) {
        removed[normalized] = (removed[normalized] ?? 0) + 1;
      }
    }
    var matches = 0;
    for (final SemanticLine line in addedLines) {
      final String normalized = _styleShape(line.text);
      final int available = removed[normalized] ?? 0;
      if (normalized.isNotEmpty && available > 0) {
        matches++;
        removed[normalized] = available - 1;
      }
    }
    return matches;
  }
}

final class SemanticLine {
  const SemanticLine(this.number, this.text);
  final int number;
  final String text;
}

List<SemanticLine> _lineDifference(String source, String other) {
  final List<String> lines = source.split('\n');
  final Map<String, int> available = <String, int>{};
  for (final String line in other.split('\n')) {
    final String normalized = line.trim();
    if (normalized.isNotEmpty) {
      available[normalized] = (available[normalized] ?? 0) + 1;
    }
  }
  final List<SemanticLine> result = <SemanticLine>[];
  for (var index = 0; index < lines.length; index++) {
    final String normalized = lines[index].trim();
    if (normalized.isEmpty) continue;
    final int count = available[normalized] ?? 0;
    if (count > 0) {
      available[normalized] = count - 1;
    } else {
      result.add(SemanticLine(index + 1, lines[index]));
    }
  }
  return List<SemanticLine>.unmodifiable(result);
}

String _styleShape(String line) => line
    .trim()
    .replaceAll(cachedRegExp(r'["\x27]'), 'Q')
    .replaceAll(cachedRegExp(r'\s+'), ' ')
    .replaceAll(cachedRegExp(r'\b(?:final|const|var)\s+'), '')
    .replaceAll(cachedRegExp(r'\s*:\s*[A-Za-z_$][\w$<>,?\[\]. ]*'), '')
    .trim();

final RegExp _testPath = cachedRegExp(
  r'(^|/)(?:test|tests|spec|specs|__tests__)(/|$)|(?:_test|\.test|\.spec)\.',
  caseSensitive: false,
);
final RegExp _behaviorLine = cachedRegExp(
  r'\b(?:if|else|for|while|switch|case|return|throw|await|yield|new)\b|[=!<>]=|\?\?',
);
final RegExp _declarationLine = cachedRegExp(
  r'^\s*(?:abstract\s+)?(?:interface|class|mixin|protocol|trait|enum|typedef|type|def|fun|function)\b',
);
const Set<String> _ignoredConcepts = <String>{
  'lib',
  'src',
  'test',
  'tests',
  'spec',
  'main',
  'index',
  'dart',
  'java',
};
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
