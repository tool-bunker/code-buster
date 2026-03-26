// Nim type declarations carry ownership, serialization, and API clues that line-oriented call checks cannot infer reliably.

import '../../core/models.dart';

/// Detects Nim type-section organization hazards.
final class NimTypeRulePack {
  /// Finds mutually recursive types split across separate type sections.
  List<Finding> analyzeFile(String path, List<String> lines) {
    final List<int> typeStarts = <int>[];
    for (var lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      if (lines[lineIndex].trim() == 'type') typeStarts.add(lineIndex);
    }
    for (var left = 0; left < typeStarts.length - 1; left++) {
      final int leftEnd = typeStarts[left + 1];
      final String leftText = lines
          .sublist(typeStarts[left], leftEnd)
          .join('\n');
      final Set<String> leftNames = _typeNames(leftText);
      for (var right = left + 1; right < typeStarts.length; right++) {
        final int rightEnd = right + 1 < typeStarts.length
            ? typeStarts[right + 1]
            : lines.length;
        final String rightText = lines
            .sublist(typeStarts[right], rightEnd)
            .join('\n');
        final Set<String> rightNames = _typeNames(rightText);
        if (leftNames.any(rightText.contains) &&
            rightNames.any(leftText.contains)) {
          return <Finding>[
            Finding(
              code: 'nim-split-recursive-types',
              severity: RuleSeverity.warn,
              path: path,
              line: typeStarts[right] + 1,
              endLine: typeStarts[right] + 1,
              message:
                  'mutually recursive types are split across type sections',
              confidence: 'medium',
              why:
                  'Nim mutually recursive object/ref types need to be declared in one type section.',
              suggestion:
                  'Merge the mutually recursive declarations into a single type block.',
            ),
          ];
        }
      }
    }
    return const <Finding>[];
  }

  Set<String> _typeNames(String source) => RegExp(
    r'^\s+([A-Za-z_]\w*)\*?\s*=',
    multiLine: true,
  ).allMatches(source).map((RegExpMatch match) => match.group(1)!).toSet();
}
