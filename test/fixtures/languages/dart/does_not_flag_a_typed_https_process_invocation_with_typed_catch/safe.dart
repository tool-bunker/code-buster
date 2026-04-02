void run(String input) {
  final url = 'https://example.test/api';
  try {
    Process.run('git', <String>['status']);
  } on ProcessException catch (error) {
    printError(error);
  }
}
