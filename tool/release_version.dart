// Prevents publishing a tag whose version disagrees with pubspec, keeping the
// package and GitHub release identities aligned.

import 'dart:io';

import 'package:code_buster/src/core/regexp_cache.dart';

const String generatedVersionPath = 'lib/src/version.dart';

void main(List<String> arguments) {
  final String pubspec = File('pubspec.yaml').readAsStringSync();
  if (arguments.length == 1 && arguments.single == '--update') {
    final String? version = extractPubspecVersion(pubspec);
    if (version == null) {
      stderr.writeln('pubspec.yaml has no version');
      exitCode = 1;
      return;
    }
    File(generatedVersionPath).writeAsStringSync(renderVersionSource(version));
    stdout.writeln(version);
    return;
  }
  if (arguments.length != 1) {
    stderr.writeln('usage: dart run tool/release_version.dart <tag>|--update');
    exitCode = 64;
    return;
  }
  final String? error = validateReleaseVersion(
    tag: arguments.single,
    pubspec: pubspec,
    changelog: File('CHANGELOG.md').readAsStringSync(),
    generatedVersionSource: File(generatedVersionPath).readAsStringSync(),
  );
  if (error != null) {
    stderr.writeln(error);
    exitCode = 1;
    return;
  }
  stdout.writeln(arguments.single.substring(1));
}

String? extractPubspecVersion(String pubspec) => RegExp(
  r'^version:\s*([^\s]+)\s*$',
  multiLine: true,
).firstMatch(pubspec)?.requiredGroup(1);

String renderVersionSource(String version) =>
    '''// Generated from pubspec.yaml by tool/release_version.dart --update.
// Do not edit by hand.

/// Code Buster package version embedded in installed and native executables.
const String codeBusterVersion = '$version';
''';

String? validateReleaseVersion({
  required String tag,
  required String pubspec,
  required String changelog,
  required String generatedVersionSource,
}) {
  final String? version = extractPubspecVersion(pubspec);
  if (version == null) return 'pubspec.yaml has no version';
  if (tag != 'v$version') {
    return 'tag $tag does not match pubspec version $version';
  }
  if (generatedVersionSource != renderVersionSource(version)) {
    return '$generatedVersionPath is not generated from pubspec version '
        '$version';
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
