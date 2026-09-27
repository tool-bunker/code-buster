import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/response_body_not_closed.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports only HTTP responses not closed in their function', () {
    final List<Finding> findings = const GoResponseBodyNotClosedRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'client.go': sourceFixture(
                'go/rules/response_body_not_closed_test/reports_only_http_responses_not_closed_in_their_function/client.go',
              ),
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'go-response-body-not-closed');
    expect(findings.single.line, 3);
  });

  test('requires HTTP client evidence for generic Do methods', () {
    final List<Finding> findings = const GoResponseBodyNotClosedRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'transport.go': '''
func exchange(transporter Transporter, message Message) error {
  response, err := transporter.Do(ctx, message)
  return err
}

func discover(client *stun.Client, transaction *stun.Transaction) error {
  response, err := client.Do(transaction)
  return err
}

func leak(client *http.Client, request *http.Request) error {
  response, err := client.Do(request)
  if err != nil {
    return err
  }
  consume(response.Body)
  return nil
}

func local(request *http.Request) error {
  c := &http.Client{}
  response, err := c.Do(request)
  if err != nil {
    return err
  }
  consume(response.Body)
  return nil
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[12, 22]);
  });

  test('accepts a response closed by a local helper', () {
    final List<Finding> findings = const GoResponseBodyNotClosedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'client.go': '''
func fetch(client *http.Client, request *http.Request) ([]byte, error) {
  response, err := client.Do(request)
  if err != nil {
    return nil, err
  }
  return decode(response)
}

func decode(response *http.Response) ([]byte, error) {
  data, err := io.ReadAll(response.Body)
  response.Body.Close()
  return data, err
}

func leak(client *http.Client, request *http.Request) error {
  response, err := client.Do(request)
  if err != nil {
    return err
  }
  return inspect(response)
}

func inspect(response *http.Response) error {
  return inspectBody(response.Body)
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 16);
  });
}
