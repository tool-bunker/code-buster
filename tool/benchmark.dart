// Tracks cold and warm analysis costs so performance-sensitive changes can
// be compared against a repeatable repository workload.

import 'dart:convert';

import 'package:code_buster/src/internal.dart';

/// Runs repeatable in-process cold/warm analysis timing for a fixture/repository.
void main(List<String> arguments) {
  final String root = arguments.isEmpty
      ? 'test/fixtures/mixed_realistic'
      : arguments.first;
  final int iterations = arguments.length > 1 ? int.parse(arguments[1]) : 5;
  final List<int> elapsed = <int>[];
  for (var index = 0; index < iterations; index++) {
    final Stopwatch stopwatch = Stopwatch()..start();
    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root]),
    );
    stopwatch.stop();
    elapsed.add(stopwatch.elapsedMicroseconds);
    if (run.files.isEmpty) throw StateError('benchmark discovered no files');
  }
  final List<int> sorted = List<int>.of(elapsed)..sort();
  print(
    jsonEncode(<String, Object>{
      'schema_version': 1,
      'root': root,
      'iterations': iterations,
      'microseconds': elapsed,
      'median_microseconds': sorted[sorted.length ~/ 2],
      'minimum_microseconds': sorted.first,
      'maximum_microseconds': sorted.last,
    }),
  );
}
