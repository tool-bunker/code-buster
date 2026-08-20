// Prevents publishing a tag whose version disagrees with pubspec, keeping the
// package and GitHub release identities aligned.

import 'dart:io';

void main(List<String> arguments) {
  if (arguments.length != 1) {
    stderr.writeln('usage: dart run tool/release_version.dart <tag>');
    exitCode = 64;
    return;
  }
  final String? error = validateReleaseVersion(
    tag: arguments.single,
    pubspec: File('pubspec.yaml').readAsStringSync(),
    changelog: File('CHANGELOG.md').readAsStringSync(),
  );
  if (error != null) {
    stderr.writeln(error);
    exitCode = 1;
    return;
  }
  stdout.writeln(arguments.single.substring(1));
}

String? validateReleaseVersion({
  required String tag,
  required String pubspec,
  required String changelog,
}) {
  final RegExpMatch? versionMatch = RegExp(
    r'^version:\s*([^\s]+)\s*$',
    multiLine: true,
  ).firstMatch(pubspec);
  if (versionMatch == null) return 'pubspec.yaml has no version';

  final String version = versionMatch.group(1)!;
  if (tag != 'v$version') {
    return 'tag $tag does not match pubspec version $version';
  }

  final RegExp heading = RegExp(
    '^## ${RegExp.escape(version)}\\s*\$',
    multiLine: true,
  );
  if (!heading.hasMatch(changelog)) {
    return 'CHANGELOG.md has no release heading for $version';
  }
  return null;
}
