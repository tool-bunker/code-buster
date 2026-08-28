// CLI integration tests share one native executable so process coverage does not repeatedly pay Dart startup and compilation costs.

import 'dart:io';

Future<String>? _resolvedExecutable;

/// Returns an up-to-date Code Buster executable shared by process-based tests.
Future<String> codeBusterTestExecutable() =>
    _resolvedExecutable ??= _resolveExecutable();

/// Runs the compiled Code Buster CLI with [arguments].
Future<ProcessResult> runCodeBuster(
  List<String> arguments, {
  String? workingDirectory,
}) async {
  final String executable = await codeBusterTestExecutable();
  final File lockFile = File('build/test/cb-process.lock').absolute;
  lockFile.parent.createSync(recursive: true);
  final RandomAccessFile lock = lockFile.openSync(mode: FileMode.append);
  await lock.lock(FileLock.exclusive);
  try {
    return await Process.run(
      executable,
      arguments,
      workingDirectory: workingDirectory ?? Directory.current.path,
    );
  } finally {
    await lock.unlock();
    await lock.close();
  }
}

Future<String> _resolveExecutable() async {
  final String? configured =
      Platform.environment['CODE_BUSTER_TEST_EXECUTABLE'];
  if (configured != null && configured.isNotEmpty) {
    final String absolute = File(configured).absolute.path;
    if (!File(absolute).existsSync()) {
      throw StateError('CODE_BUSTER_TEST_EXECUTABLE does not exist: $absolute');
    }
    return absolute;
  }

  final String suffix = Platform.isWindows ? '.exe' : '';
  final File executable = File('build/test/cb-test$suffix').absolute;
  final File lockFile = File('build/test/cb-test.lock').absolute;
  executable.parent.createSync(recursive: true);
  final RandomAccessFile lock = lockFile.openSync(mode: FileMode.append);
  await lock.lock(FileLock.exclusive);
  try {
    if (_needsBuild(executable)) {
      final ProcessResult result = await Process.run(
        Platform.resolvedExecutable,
        <String>['compile', 'exe', 'bin/cb.dart', '-o', executable.path],
        workingDirectory: Directory.current.path,
      );
      if (result.exitCode != 0) {
        throw StateError(
          'failed to compile CLI test executable:\n${result.stdout}${result.stderr}',
        );
      }
    }
  } finally {
    await lock.unlock();
    await lock.close();
  }
  return executable.path;
}

bool _needsBuild(File executable) {
  if (!executable.existsSync()) return true;
  final DateTime built = executable.lastModifiedSync();
  for (final String root in <String>['bin', 'lib']) {
    for (final File file in Directory(
      root,
    ).listSync(recursive: true).whereType<File>()) {
      if (file.path.endsWith('.dart') &&
          file.lastModifiedSync().isAfter(built)) {
        return true;
      }
    }
  }
  for (final String manifest in <String>['pubspec.yaml', 'pubspec.lock']) {
    final File file = File(manifest);
    if (file.existsSync() && file.lastModifiedSync().isAfter(built)) {
      return true;
    }
  }
  return false;
}
