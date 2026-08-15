import 'a.dart';

void main() {
  print('debug');
  final String url = 'http://example.test';
  final String command = 'echo';
  Process.run(command, const <String>[]);
  Flags.featureEnabled();
  try {
    throw StateError('failure');
  } catch (_) {}
  complex();
  duplicate();
}

void complex() {
  if (true) {
    if (false) {
      print('nested');
    }
  }
}

void unused<T>() {}

void duplicate() {
  final int alpha = 1;
  final int beta = 2;
  print(alpha + beta);
}

void duplicateAgain() {
  final int alpha = 1;
  final int beta = 2;
  print(alpha + beta);
}

bool repeatedOne(int value) {
  if (value > 0 && value < 10) return true;
  return false;
}

bool repeatedTwo(int value) {
  if (value > 0 && value < 10) return true;
  return false;
}

bool repeatedThree(int value) {
  if (value > 0 && value < 10) return true;
  return false;
}
