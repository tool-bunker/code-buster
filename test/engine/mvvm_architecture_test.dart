import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/architecture/mvvm_architecture.dart';
import 'package:test/test.dart';

void main() {
  final AnalysisConfig config = AnalysisConfig(
    root: '.',
    architectureProfile: 'dart-mvvm',
  );

  test('classifies conventional and suffix-based MVVM paths', () {
    final MvvmPathClassifier classifier = MvvmPathClassifier(config);
    expect(
      classifier.classify('lib/login/views/login_page.dart'),
      MvvmLayer.view,
    );
    expect(
      classifier.classify('lib/login/login_view_model.dart'),
      MvvmLayer.viewModel,
    );
    expect(classifier.classify('lib/domain/user.dart'), MvvmLayer.model);
    expect(
      classifier.classify('lib/login/data/user_repository.dart'),
      MvvmLayer.repository,
    );
  });

  test('reports forbidden MVVM graph direction', () {
    final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
      'lib/login/views/login_page.dart': <String>[
        'lib/login/data/login_repository.dart',
      ],
      'lib/login/view_models/login_view_model.dart': <String>[
        'lib/login/views/login_page.dart',
      ],
      'lib/domain/models/user.dart': <String>[
        'lib/login/view_models/login_view_model.dart',
      ],
    });

    final List<Finding> findings = MvvmArchitectureAnalysis(
      graph,
      config,
    ).findings();
    expect(findings, hasLength(3));
    expect(findings.map((Finding finding) => finding.code).toSet(), <String>{
      'mvvm-forbidden-dependency',
    });
  });

  test('does nothing unless the profile is selected', () {
    final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
      'lib/views/a.dart': <String>['lib/data/b.dart'],
    });
    expect(
      MvvmArchitectureAnalysis(
        graph,
        const AnalysisConfig(root: '.'),
      ).findings(),
      isEmpty,
    );
  });
}
