import 'dart:convert';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  const Finding finding = Finding(
    code: 'demo-rule',
    severity: RuleSeverity.warn,
    path: 'lib/demo.dart',
    line: 3,
    endLine: 5,
    message: 'Use <safe> & explicit values',
    confidence: 'high',
    why: 'Implicit behavior is hard to review.',
    suggestion: 'Use a named value.',
    relatedFiles: <String>['lib/other.dart:2'],
  );
  final FindingReporter reporter = FindingReporter();

  test('renders human text and Markdown with locations and detail', () {
    final String text = reporter.render(
      format: ReportFormat.text,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
      verbose: true,
    );
    final String markdown = reporter.render(
      format: ReportFormat.markdown,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );

    expect(text, contains('warn demo-rule lib/demo.dart:3-5'));
    expect(text, contains('why: Implicit behavior is hard to review.'));
    expect(markdown, contains('| `demo-rule` | `lib/demo.dart:3-5` |'));
    expect(markdown, contains('Use <safe> & explicit values'));
  });

  test('colors human reports only when requested', () {
    final String colored = reporter.render(
      format: ReportFormat.text,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
      color: true,
    );
    final String plain = reporter.render(
      format: ReportFormat.text,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );

    expect(colored, contains('\u001b[1;36mCode Buster summary\u001b[0m'));
    expect(colored, contains('\u001b[33mwarn\u001b[0m'));
    expect(colored, contains('\u001b[2mlib/demo.dart:3-5\u001b[0m'));
    expect(plain, isNot(contains('\u001b[')));
  });

  test('summarizes advisory findings without rendering their details', () {
    final String text = reporter.render(
      format: ReportFormat.text,
      command: 'summary',
      root: '/project',
      files: 2,
      findings: const <Finding>[],
      advisorySummary: const <String, int>{
        'maintainability': 4,
        'performance': 2,
      },
    );
    final Map<String, dynamic> json =
        jsonDecode(
              reporter.render(
                format: ReportFormat.json,
                command: 'summary',
                root: '/project',
                files: 2,
                findings: const <Finding>[],
                advisorySummary: const <String, int>{
                  'maintainability': 4,
                  'performance': 2,
                },
              ),
            )
            as Map<String, dynamic>;

    expect(text, contains('0 actionable findings'));
    expect(text, contains('advisory    6 findings'));
    expect(text, isNot(contains('warn complex-function')));
    expect(json['actionableFindingCount'], 0);
    expect((json['advisorySummary'] as Map<String, dynamic>)['total'], 6);
  });

  test('renders JSON and NDJSON machine contracts', () {
    final String json = reporter.render(
      format: ReportFormat.json,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );
    final String ndjson = reporter.render(
      format: ReportFormat.ndjson,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );

    final Map<String, dynamic> envelope =
        jsonDecode(json) as Map<String, dynamic>;
    expect(envelope['schemaVersion'], reportSchemaVersion);
    expect(envelope['version'], 1);
    final List<dynamic> envelopeFindings =
        envelope['findings']! as List<dynamic>;
    final Map<String, dynamic> jsonFinding =
        envelopeFindings.single as Map<String, dynamic>;
    expect(jsonFinding['end_line'], 5);
    final List<Map<String, dynamic>> ndjsonRecords = ndjson
        .split('\n')
        .map((String line) => jsonDecode(line) as Map<String, dynamic>)
        .toList(growable: false);
    expect(ndjsonRecords.first['recordType'], 'summary');
    expect(ndjsonRecords.first['actionableFindingCount'], 1);
    expect(ndjsonRecords.last['schemaVersion'], reportSchemaVersion);
    expect(ndjsonRecords.last['recordType'], 'finding');
    expect(ndjsonRecords.last['code'], 'demo-rule');
  });

  test('separates security hotspots from confirmed vulnerabilities', () {
    final String output = reporter.render(
      format: ReportFormat.json,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: const <Finding>[
        Finding(
          code: 'go-shell-command',
          severity: RuleSeverity.warn,
          path: 'main.go',
          line: 1,
          message: 'review shell use',
          codeFlow: <CodeFlowStep>[
            CodeFlowStep(
              path: 'main.go',
              line: 1,
              message: 'shell execution sink',
            ),
          ],
        ),
        Finding(
          code: 'go-insecure-tls',
          severity: RuleSeverity.error,
          path: 'main.go',
          line: 2,
          message: 'verification disabled',
        ),
      ],
    );
    final List<Map<String, dynamic>> findings =
        ((jsonDecode(output) as Map<String, dynamic>)['findings']
                as List<dynamic>)
            .cast<Map<String, dynamic>>();
    expect(findings[0]['security_kind'], 'hotspot');
    expect(findings[0]['code_flow'], hasLength(1));
    expect(findings[1]['security_kind'], 'vulnerability');

    final Map<String, dynamic> sarif =
        jsonDecode(
              reporter.render(
                format: ReportFormat.sarif,
                command: 'summary',
                root: '/project',
                files: 1,
                findings: const <Finding>[
                  Finding(
                    code: 'go-shell-command',
                    severity: RuleSeverity.warn,
                    path: 'main.go',
                    line: 1,
                    message: 'review shell use',
                    codeFlow: <CodeFlowStep>[
                      CodeFlowStep(
                        path: 'main.go',
                        line: 1,
                        message: 'shell execution sink',
                      ),
                    ],
                  ),
                ],
              ),
            )
            as Map<String, dynamic>;
    final Map<String, dynamic> run =
        (sarif['runs'] as List<dynamic>).single as Map<String, dynamic>;
    final Map<String, dynamic> result =
        (run['results'] as List<dynamic>).single as Map<String, dynamic>;
    expect(result['codeFlows'], hasLength(1));
  });

  test('renders SARIF 2.1.0 and JUnit with XML escaping', () {
    final String sarif = reporter.render(
      format: ReportFormat.sarif,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );
    final String junit = reporter.render(
      format: ReportFormat.junit,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: <Finding>[finding],
    );

    final Map<String, dynamic> document =
        jsonDecode(sarif) as Map<String, dynamic>;
    expect(document['version'], '2.1.0');
    final List<dynamic> runs = document['runs']! as List<dynamic>;
    final Map<String, dynamic> run = runs.single as Map<String, dynamic>;
    expect(
      (run['properties']!
          as Map<String, dynamic>)['codeBusterReportSchemaVersion'],
      reportSchemaVersion,
    );
    final List<dynamic> results = run['results']! as List<dynamic>;
    final Map<String, dynamic> sarifFinding =
        results.single as Map<String, dynamic>;
    expect(sarifFinding['level'], 'warning');
    expect(junit, contains('message="Use &lt;safe&gt; &amp; explicit values"'));
    expect(
      junit,
      contains('warn lib/demo.dart:3-5 Use &lt;safe&gt; &amp; explicit values'),
    );
  });

  test('rejects unknown report formats', () {
    expect(() => ReportFormat.parse('yaml'), throwsFormatException);
  });
}
