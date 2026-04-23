import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('MVVM profile runs graph and Dart semantic checks end to end', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-mvvm-',
    );
    addTearDown(() => root.delete(recursive: true));
    File('${root.path}/code-buster.toml').writeAsStringSync('''
languages = ["dart"]
[architecture]
profile = "dart-mvvm"
''');
    Directory('${root.path}/lib/views').createSync(recursive: true);
    Directory('${root.path}/lib/view_models').createSync(recursive: true);
    Directory('${root.path}/lib/models').createSync(recursive: true);
    Directory('${root.path}/lib/data').createSync(recursive: true);
    File('${root.path}/lib/views/login_page.dart').writeAsStringSync(
      "import '../data/login_repository.dart';\nclass LoginPage {}\n",
    );
    File(
      '${root.path}/lib/data/login_repository.dart',
    ).writeAsStringSync('class LoginRepository {}\n');
    File('${root.path}/lib/models/user_model.dart').writeAsStringSync(
      "import 'package:flutter/widgets.dart';\nclass UserModel {}\n",
    );
    File(
      '${root.path}/lib/view_models/login_view_model.dart',
    ).writeAsStringSync('''
class LoginViewModel {
  void open(BuildContext context) => Navigator.of(context);
}
''');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );
    final Set<String> codes = run.findings
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>[
        'mvvm-forbidden-dependency',
        'mvvm-model-imports-ui',
        'mvvm-viewmodel-ui-context',
        'mvvm-viewmodel-performs-navigation',
      ]),
    );
  });
}
