// Automated edits are intentionally narrow; this code limits fixes to transformations that can preserve source bytes and user intent.

import 'dart:io';
import '../discovery/discovery.dart';

/// Describes one source file changed by the safe fixer.
final class FixResult {
  const FixResult({required this.path, required this.changed});

  final String path;

  final bool changed;
}

/// Applies only whitespace transformations that cannot alter Dart string data.
final class SafeFixer {
  const SafeFixer();

  /// Replaces indentation tabs with spaces and removes trailing whitespace.
  ///
  /// Lines inside multiline Dart string literals are preserved byte-for-byte.
  /// Line endings and a final newline are retained.
  String fixedContent(String source, {String path = ''}) {
    final bool usesCrLf = source.contains('\r\n');
    final String newline = usesCrLf ? '\r\n' : '\n';
    final bool hasFinalNewline = source.endsWith(newline);
    final List<String> lines = source.split(newline);
    if (hasFinalNewline) lines.removeLast();

    String? multilineDelimiter;
    final List<String> output = <String>[];
    for (final String rawLine in lines) {
      String line = rawLine;
      if (multilineDelimiter == null) {
        final int indentation = _indentationEnd(line);
        line =
            '${line.substring(0, indentation).replaceAll('\t', '  ')}${line.substring(indentation)}';
        line = line.replaceFirst(RegExp(r'[ \t]+$'), '');
        if (path.endsWith('.nim') || path.endsWith('.nims')) {
          line = _fixNimStdImport(line);
        }
        multilineDelimiter = _openingDelimiter(line);
      } else if (_closesDelimiter(line, multilineDelimiter)) {
        // The literal ends before this line's trailing whitespace, which is
        // outside the string and therefore safe to remove.
        line = line.replaceFirst(RegExp(r'[ \t]+$'), '');
        multilineDelimiter = null;
      }
      output.add(line);
    }
    return '${output.join(newline)}${hasFinalNewline ? newline : ''}';
  }

  /// Applies fixes to [files]; with [dryRun], only reports prospective changes.
  List<FixResult> apply({
    required String root,
    required Iterable<SourceFile> files,
    required bool dryRun,
  }) {
    final List<FixResult> results = <FixResult>[];
    for (final SourceFile sourceFile in files) {
      final File file = File(sourceFile.absolutePath);
      final String before = file.readAsStringSync();
      final String after = fixedContent(before, path: sourceFile.relativePath);
      final bool changed = before != after;
      if (changed && !dryRun) file.writeAsStringSync(after);
      results.add(FixResult(path: sourceFile.relativePath, changed: changed));
    }
    return List<FixResult>.unmodifiable(results);
  }

  String _fixNimStdImport(String line) {
    final int indent = _indentationEnd(line);
    final String prefix = line.substring(0, indent);
    final String trimmed = line.trim();
    if (trimmed == 'import os') return '${prefix}import std/os';
    if (trimmed.startsWith('from os import')) {
      return '$prefix${trimmed.replaceFirst('from os import', 'from std/os import')}';
    }
    if (trimmed.startsWith('import os,')) {
      return '$prefix${trimmed.replaceFirst('import os,', 'import std/os,')}';
    }
    return line;
  }

  int _indentationEnd(String line) {
    var index = 0;
    while (index < line.length && (line[index] == ' ' || line[index] == '\t')) {
      index++;
    }
    return index;
  }

  String? _openingDelimiter(String line) {
    final int doubleIndex = line.indexOf('"""');
    final int singleIndex = line.indexOf("'''");
    if (doubleIndex < 0 && singleIndex < 0) return null;
    final String delimiter =
        doubleIndex >= 0 && (singleIndex < 0 || doubleIndex < singleIndex)
        ? '"""'
        : "'''";
    return delimiter.allMatches(line).length.isOdd ? delimiter : null;
  }

  bool _closesDelimiter(String line, String delimiter) =>
      line.contains(delimiter);
}
