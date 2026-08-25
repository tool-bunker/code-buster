// GitHub releases should carry the reviewed changelog entry instead of only an automatically generated commit list.

import 'dart:io';

void main(List<String> arguments) {
  if (arguments.length != 2) {
    stderr.writeln(
      'usage: dart run tool/release_notes.dart <tag> <output-file>',
    );
    exitCode = 64;
    return;
  }

  try {
    final String notes = extractReleaseNotes(
      changelog: File('CHANGELOG.md').readAsStringSync(),
      tag: arguments[0],
    );
    final File output = File(arguments[1]);
    output.parent.createSync(recursive: true);
    output.writeAsStringSync(notes);
    stdout.writeln(output.path);
  } on FormatException catch (error) {
    stderr.writeln(error.message);
    exitCode = 1;
  }
}

/// Returns the Markdown body under the release heading matching [tag].
String extractReleaseNotes({required String changelog, required String tag}) {
  if (!tag.startsWith('v') || tag.length == 1) {
    throw FormatException('release tag must have the form v<version>: $tag');
  }
  final String version = tag.substring(1);
  final RegExp heading = RegExp(
    '^## ${RegExp.escape(version)}\\s*${r'$'}',
    multiLine: true,
  );
  final RegExpMatch? match = heading.firstMatch(changelog);
  if (match == null) {
    throw FormatException('CHANGELOG.md has no release heading for $version');
  }

  final int bodyStart = match.end;
  final RegExpMatch? nextHeading = RegExp(
    r'^##\s+',
    multiLine: true,
  ).firstMatch(changelog.substring(bodyStart));
  final int bodyEnd = nextHeading == null
      ? changelog.length
      : bodyStart + nextHeading.start;
  final String body = changelog.substring(bodyStart, bodyEnd).trim();
  if (body.isEmpty) {
    throw FormatException('CHANGELOG.md release $version has no notes');
  }
  return '$body\n';
}
