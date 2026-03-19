// C and C++ share much syntax but not every convention; this adapter extracts their imports and callable regions without pretending to compile them.

import 'package:path/path.dart' as path;

import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Local include resolution, function extraction, and Core-Guidelines checks.
final class CppAdapter {
  /// Builds dependencies for quoted local `#include` directives.
  DependencyGraph buildGraph(Map<String, String> sources) {
    final Set<String> known = sources.keys.toSet();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    for (final String sourcePath in sources.keys.toList()..sort()) {
      final Set<String> dependencies = <String>{};
      for (final RegExpMatch match in _include.allMatches(
        sources[sourcePath]!,
      )) {
        final String include = match.group(1)!;
        final String relative = path.posix.normalize(
          path.posix.join(path.posix.dirname(sourcePath), include),
        );
        for (final String candidate in <String>[
          relative,
          include,
          ..._withExtensions(relative),
          ..._withExtensions(include),
        ]) {
          if (known.contains(candidate)) {
            dependencies.add(candidate);
            break;
          }
        }
      }
      edges[sourcePath] = dependencies;
    }
    return DependencyGraph(edges);
  }

  /// Extracts brace-delimited C and C++ function bodies for complexity analysis.
  List<FunctionSource> functions(Map<String, String> sources) {
    final List<FunctionSource> result = <FunctionSource>[];
    final Set<String> stringifyingMacros = _stringifyingMacros(sources.values);
    for (final MapEntry<String, String> entry in sources.entries) {
      final List<String> lines = _maskStringifyingMacroArguments(
        maskDefinitelyInactivePreprocessorBranches(
          _maskStringsAndComments(entry.value).split('\n'),
        ),
        stringifyingMacros,
      );
      for (var index = 0; index < lines.length; index++) {
        final String firstLine = lines[index];
        final String trimmedFirstLine = firstLine.trimLeft();
        if (_control.hasMatch(trimmedFirstLine) ||
            trimmedFirstLine.startsWith(':') ||
            trimmedFirstLine.startsWith('typedef ')) {
          continue;
        }
        RegExpMatch? declaration =
            _objectiveCMethod.firstMatch(firstLine) ??
            _function.firstMatch(firstLine);
        if (declaration == null &&
            (_unqualifiedSignature.hasMatch(firstLine) ||
                _qualifiedSignature.hasMatch(firstLine) ||
                _objectiveCSignature.hasMatch(firstLine))) {
          final StringBuffer signature = StringBuffer();
          for (
            var signatureEnd = index;
            signatureEnd < lines.length && signatureEnd <= index + 20;
            signatureEnd++
          ) {
            signature.writeln(lines[signatureEnd]);
            if (lines[signatureEnd].contains('{') ||
                lines[signatureEnd].contains(';')) {
              break;
            }
          }
          final String multiline = signature.toString();
          declaration =
              _objectiveCMethod.firstMatch(multiline) ??
              _function.firstMatch(multiline);
        }
        if (declaration == null ||
            _controlName.hasMatch(declaration.group(1)!)) {
          continue;
        }
        var depth = 0;
        var end = index;
        var started = false;
        for (; end < lines.length; end++) {
          for (final int rune in lines[end].runes) {
            if (rune == 123) {
              depth++;
              started = true;
            } else if (rune == 125) {
              depth--;
            }
          }
          if (started && depth <= 0) {
            break;
          }
        }
        result.addAll(
          _functionAndLambdas(
            path: entry.key,
            name: declaration.group(1)!,
            line: index + 1,
            source: lines
                .sublist(index, (end + 1).clamp(0, lines.length))
                .join('\n'),
          ),
        );
        index = end;
      }
    }
    return result;
  }

  static List<FunctionSource> _functionAndLambdas({
    required String path,
    required String name,
    required int line,
    required String source,
  }) {
    final String masked = _maskStringsAndComments(source);
    final Map<int, ({int start, int end})> lambdas =
        <int, ({int start, int end})>{};
    for (final RegExpMatch match in _lambda.allMatches(masked)) {
      final int opening = masked.indexOf('{', match.start);
      if (opening < 0 || opening >= match.end) continue;
      final int end = _matchingBrace(masked, opening);
      if (end >= 0) lambdas[opening] = (start: match.start, end: end);
    }

    final List<FunctionSource> result = <FunctionSource>[
      FunctionSource(
        path: path,
        name: name,
        line: line,
        source: _withoutNestedLambdas(
          source,
          start: 0,
          opening: -1,
          end: source.length - 1,
          lambdas: lambdas,
        ),
      ),
    ];
    for (final int opening in lambdas.keys.toList()..sort()) {
      final ({int start, int end}) lambda = lambdas[opening]!;
      result.add(
        FunctionSource(
          path: path,
          name: '<lambda>',
          line:
              line + '\n'.allMatches(source.substring(0, lambda.start)).length,
          source: _withoutNestedLambdas(
            source,
            start: lambda.start,
            opening: opening,
            end: lambda.end,
            lambdas: lambdas,
          ),
        ),
      );
    }
    return result;
  }

  static String _withoutNestedLambdas(
    String source, {
    required int start,
    required int opening,
    required int end,
    required Map<int, ({int start, int end})> lambdas,
  }) {
    final List<int> result = source
        .substring(start, end + 1)
        .codeUnits
        .toList();
    for (final MapEntry<int, ({int start, int end})> entry in lambdas.entries) {
      if (entry.key <= opening || entry.value.end > end) continue;
      for (
        var index = entry.value.start - start;
        index <= entry.value.end - start;
        index++
      ) {
        if (result[index] != 10 && result[index] != 13) result[index] = 32;
      }
    }
    return String.fromCharCodes(result);
  }

  static int _matchingBrace(String source, int opening) {
    var depth = 0;
    for (var index = opening; index < source.length; index++) {
      if (source.codeUnitAt(index) == 123) depth++;
      if (source.codeUnitAt(index) == 125 && --depth == 0) return index;
    }
    return -1;
  }

  static String _maskStringsAndComments(String source) {
    final List<int> result = source.codeUnits.toList();
    var index = 0;
    while (index < result.length) {
      final int current = result[index];
      if (current == 47 &&
          index + 1 < result.length &&
          result[index + 1] == 47) {
        while (index < result.length && result[index] != 10) {
          result[index++] = 32;
        }
        continue;
      }
      if (current == 47 &&
          index + 1 < result.length &&
          result[index + 1] == 42) {
        result[index++] = 32;
        result[index++] = 32;
        while (index + 1 < result.length &&
            !(result[index] == 42 && result[index + 1] == 47)) {
          if (result[index] != 10 && result[index] != 13) result[index] = 32;
          index++;
        }
        if (index + 1 < result.length) {
          result[index++] = 32;
          result[index++] = 32;
        }
        continue;
      }
      if (current == 34 || current == 39) {
        final int quote = current;
        result[index++] = 32;
        while (index < result.length) {
          if (result[index] == 92) {
            result[index++] = 32;
            if (index < result.length &&
                result[index] != 10 &&
                result[index] != 13) {
              result[index++] = 32;
            }
            continue;
          }
          if (result[index] == quote) {
            result[index++] = 32;
            break;
          }
          if (result[index] != 10 && result[index] != 13) result[index] = 32;
          index++;
        }
        continue;
      }
      index++;
    }
    return String.fromCharCodes(result);
  }

  static final RegExp _lambda = RegExp(
    r'\[[^\]\r\n]*\]\s*(?:\([^;{}]*\))?\s*(?:(?:mutable|constexpr|consteval)\s+)*(?:noexcept(?:\s*\([^)]*\))?\s*)?(?:->\s*[^{}]+)?\{',
    multiLine: true,
  );

  static Set<String> _stringifyingMacros(Iterable<String> sources) {
    final Map<String, ({String parameter, String replacement})> definitions =
        <String, ({String parameter, String replacement})>{};
    for (final String source in sources) {
      for (final RegExpMatch definition in _functionMacroDefinition.allMatches(
        source,
      )) {
        definitions[definition.group(1)!] = (
          parameter: definition.group(2)!,
          replacement: definition.group(3)!,
        );
      }
    }

    final Set<String> result = <String>{};
    for (final MapEntry<String, ({String parameter, String replacement})>
        definition
        in definitions.entries) {
      final String parameter = RegExp.escape(definition.value.parameter);
      if (RegExp(
        '(^|[^#])#\\s*$parameter\\b',
      ).hasMatch(definition.value.replacement)) {
        result.add(definition.key);
      }
    }

    var changed = true;
    while (changed) {
      changed = false;
      for (final MapEntry<String, ({String parameter, String replacement})>
          definition
          in definitions.entries) {
        if (result.contains(definition.key)) continue;
        final String parameter = RegExp.escape(definition.value.parameter);
        if (result.any(
          (String stringifier) => RegExp(
            '\\b${RegExp.escape(stringifier)}\\s*\\(\\s*$parameter\\s*\\)',
          ).hasMatch(definition.value.replacement),
        )) {
          result.add(definition.key);
          changed = true;
        }
      }
    }
    return result;
  }

  static List<String> _maskStringifyingMacroArguments(
    List<String> lines,
    Set<String> macroNames,
  ) {
    if (macroNames.isEmpty) return lines;
    final String source = lines.join('\n');
    final List<int> masked = source.codeUnits.toList();
    final RegExp invocation = RegExp(
      '\\b(?:${macroNames.map(RegExp.escape).join('|')})\\s*\\(',
    );
    for (final RegExpMatch match in invocation.allMatches(source)) {
      final int lineStart = source.lastIndexOf('\n', match.start) + 1;
      if (RegExp(
        r'^\s*#\s*define\b',
      ).hasMatch(source.substring(lineStart, match.start))) {
        continue;
      }
      final int open = source.indexOf('(', match.start);
      final int close = _matchingParenthesis(source, open);
      if (close < 0) continue;
      for (var index = open + 1; index < close; index++) {
        if (masked[index] != 10 && masked[index] != 13) masked[index] = 32;
      }
    }
    return String.fromCharCodes(masked).split('\n');
  }

  static int _matchingParenthesis(String source, int open) {
    var depth = 0;
    int? quote;
    var escaped = false;
    var lineComment = false;
    var blockComment = false;
    for (var index = open; index < source.length; index++) {
      final int current = source.codeUnitAt(index);
      final int? next = index + 1 < source.length
          ? source.codeUnitAt(index + 1)
          : null;
      if (lineComment) {
        if (current == 10 || current == 13) lineComment = false;
        continue;
      }
      if (blockComment) {
        if (current == 42 && next == 47) {
          blockComment = false;
          index++;
        }
        continue;
      }
      if (quote != null) {
        if (escaped) {
          escaped = false;
        } else if (current == 92) {
          escaped = true;
        } else if (current == quote) {
          quote = null;
        }
        continue;
      }
      if (current == 47 && next == 47) {
        lineComment = true;
      } else if (current == 47 && next == 42) {
        blockComment = true;
        index++;
      } else if (current == 34 || current == 39) {
        quote = current;
      } else if (current == 40) {
        depth++;
      } else if (current == 41 && --depth == 0) {
        return index;
      }
    }
    return -1;
  }

  static final RegExp _functionMacroDefinition = RegExp(
    r'^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s+([^\r\n]+)$',
    multiLine: true,
  );
  static final RegExp _include = RegExp(
    r'^\s*#\s*(?:include|import)\s*"([^"]+)"',
    multiLine: true,
  );
  static final RegExp _function = RegExp(
    r'(?:^|[\s*&])(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{',
  );
  static final RegExp _unqualifiedSignature = RegExp(
    r'^\s*(?!if\b|for\b|while\b|switch\b|catch\b)(?:[A-Za-z_]\w*[\s*&]+)+[A-Za-z_]\w*\s*\(',
  );
  static final RegExp _objectiveCSignature = RegExp(r'^\s*[-+]\s*\(');
  static final RegExp _qualifiedSignature = RegExp(
    r'^\s*(?:[A-Za-z_]\w*::)+(?:~?[A-Za-z_]\w*)\s*\(',
  );
  static final RegExp _controlName = RegExp(r'^(?:if|for|while|switch|catch)$');
  static final RegExp _objectiveCMethod = RegExp(
    r'^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)[^;{}]*\{',
  );
  static final RegExp _control = RegExp(r'^(?:if|for|while|switch|catch)\b');
  static const List<String> _extensions = <String>[
    '.h',
    '.hh',
    '.hpp',
    '.c',
    '.cc',
    '.cpp',
    '.cxx',
    '.m',
    '.mm',
  ];
  static Iterable<String> _withExtensions(String value) sync* {
    if (path.posix.extension(value).isEmpty) {
      for (final String extension in _extensions) {
        yield '$value$extension';
      }
    }
  }
}
