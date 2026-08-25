// Java rules repeatedly need strings and comments masked; this utility keeps their line checks from matching inert text.

/// Removes Java comments while preserving code and quoted literals.
///
/// Replaced comment characters remain as spaces so match offsets stay stable.
({String code, bool inBlockComment}) javaCodeWithoutComments(
  String line, {
  required bool inBlockComment,
}) {
  final StringBuffer result = StringBuffer();
  String? quote;
  for (var index = 0; index < line.length; index++) {
    final String character = line[index];
    final String next = index + 1 < line.length ? line[index + 1] : '';
    if (inBlockComment) {
      result.write(' ');
      if (character == '*' && next == '/') {
        inBlockComment = false;
        result.write(' ');
        index++;
      }
      continue;
    }
    if (quote != null) {
      result.write(character);
      if (character == '\\' && next.isNotEmpty) {
        result.write(next);
        index++;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == '/' && next == '/') {
      result.write(' ' * (line.length - index));
      break;
    }
    if (character == '/' && next == '*') {
      inBlockComment = true;
      result.write('  ');
      index++;
      continue;
    }
    result.write(character);
    if (character == '"' || character == "'") {
      quote = character;
    }
  }
  return (code: result.toString(), inBlockComment: inBlockComment);
}

/// Removes comments from a complete Java source while preserving line numbers.
String javaSourceWithoutComments(String source) {
  var inBlockComment = false;
  return source
      .split('\n')
      .map((String line) {
        final ({String code, bool inBlockComment}) masked =
            javaCodeWithoutComments(line, inBlockComment: inBlockComment);
        inBlockComment = masked.inBlockComment;
        return masked.code;
      })
      .join('\n');
}
