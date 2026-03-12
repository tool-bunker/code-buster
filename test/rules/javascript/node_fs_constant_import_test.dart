import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/javascript/node_fs_constant_import.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports multiline and aliased direct Node fs constants', () {
    final List<Finding> findings = const JavaScriptNodeFsConstantImportRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.mjs': sourceFixture(
                'javascript/rules/node_fs_constant_import_test/reports_multiline_and_aliased_direct_node_fs_constants/source.js',
              ),
            },
            language: 'javascript',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'js-node-fs-constant-import');
    expect(findings.single.message, contains('R_OK, W_OK'));
  });

  test('accepts constants namespace imports and unrelated exports', () {
    final Iterable<Finding> findings =
        const JavaScriptNodeFsConstantImportRule().analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.mjs': '''import { constants, readFileSync } from "node:fs";
const readable = constants.R_OK;
''',
            },
            language: 'javascript',
          ),
        );

    expect(findings, isEmpty);
  });
}
