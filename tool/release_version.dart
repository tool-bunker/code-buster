// Prevents publishing a tag whose version disagrees with pubspec, keeping the
// package and GitHub release identities aligned.

import 'dart:io';

void main(List<String> arguments) {
  if (arguments.length != 1) {
    stderr.writeln('usage: dart run tool/release_version.dart <tag>');
    exitCode = 64;
    return;
  }
  final String tag = arguments.single;
  final String pubspec = File('pubspec.yaml').readAsStringSync();
  final RegExpMatch? versionMatch = RegExp(
    r'^version:\s*([^\s]+)\s*$',
    multiLine: true,
  ).firstMatch(pubspec);
  if (versionMatch == null) {
    stderr.writeln('pubspec.yaml has no version');
    exitCode = 1;
    return;
  }
  final String version = versionMatch.group(1)!;
  if (tag != 'v$version') {
    stderr.writeln('tag $tag does not match pubspec version $version');
    exitCode = 1;
    return;
  }
  stdout.writeln(version);
}
