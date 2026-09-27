import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/csharp/oop_rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports an exact typed C# parameter group across files', () {
    final List<Finding> findings = _findings(<String, String>{
      'Create.cs': '''
class CreateService {
  public void Create(string tenant, int region, bool active) { }
  public void Update(string tenant, int region, bool active) { }
}
''',
      'Delete.cs': '''
class DeleteService {
  public void Delete(
    string tenant,
    int region,
    bool active
  ) { }
  public void Similar(string tenant, int region) { }
}
''',
    });

    final Finding finding = findings.singleWhere(
      (finding) => finding.code == 'oop-data-clump',
    );
    expect(finding.path, 'Create.cs');
    expect(finding.relatedFiles, <String>['Delete.cs']);
  });

  test('reports interfaces rejected by several direct implementors', () {
    final List<Finding> findings = _findings(<String, String>{
      'Storage.cs': '''
public interface IStorage {
  void Read();
  void Write();
  void Delete();
  void Archive();
}
''',
      'Cold.cs': '''
class ColdStorage : IStorage {
  public void Read() { }
  public void Write() { throw new NotSupportedException(); }
  public void Delete() { throw new NotImplementedException(); }
  public void Archive() { }
}
''',
      'ReadOnly.cs': '''
class ReadOnlyStorage : IStorage {
  public void Read() { }
  public void Write() { throw new NotSupportedException(); }
  public void Delete() { }
  public void Archive() { throw new NotImplementedException(); }
}
''',
    });

    final Finding finding = findings.singleWhere(
      (finding) => finding.code == 'oop-interface-segregation-pressure',
    );
    expect(finding.path, 'Storage.cs');
    expect(finding.relatedFiles, <String>['Cold.cs', 'ReadOnly.cs']);
  });

  test('reports inherited operations rejected by direct subclasses', () {
    final List<Finding> findings = _findings(<String, String>{
      'Channel.cs': '''
class Channel {
  public virtual void Open() { }
  public virtual void Close() { }
  public virtual void Send() { }
  public virtual void Receive() { }
}
''',
      'Input.cs': '''
class InputChannel : Channel {
  public override void Send() { throw new NotSupportedException(); }
  public override void Close() { throw new NotImplementedException(); }
}
''',
      'Output.cs': '''
class OutputChannel : Channel {
  public override void Receive() { throw new NotSupportedException(); }
  public override void Open() { throw new NotImplementedException(); }
}
''',
    });

    final Finding finding = findings.singleWhere(
      (finding) => finding.code == 'oop-refused-bequest',
    );
    expect(finding.path, 'Channel.cs');
    expect(finding.relatedFiles, <String>['Input.cs', 'Output.cs']);
  });

  test('reports a predominantly unchanged C# forwarding wrapper', () {
    final List<Finding> findings = _findings(<String, String>{
      'Gateway.cs': '''
class Gateway {
  private readonly Client _client;
  public Result Load(Id id) => _client.Load(id);
  public Result Save(Id id) { return _client.Save(id); }
  public Result Delete(Id id) => _client.Delete(id);
  public Result Refresh(Id id) => _client.Refresh(id);
  public Result Inspect(Id id) => _client.Inspect(id);
}
''',
    });

    final Finding finding = findings.singleWhere(
      (finding) => finding.code == 'oop-middle-man-delegation',
    );
    expect(finding.path, 'Gateway.cs');
    expect(finding.message, contains('5 of 5'));
  });

  test(
    'ignores partial patterns, intentional boundaries, comments, and strings',
    () {
      final List<Finding> findings = _findings(<String, String>{
        'Safe.cs': '''
// class Fake { public void Run(string tenant, int region, bool active) { } }
class SafeGateway : IGateway {
  private readonly Client _client;
  public Result Load(Id id) => _client.Load(id);
  public Result Save(Id id) => _client.Save(id);
  public Result Delete(Id id) => _client.Delete(id);
  public Result Refresh(Id id) => _client.Refresh(id);
  public Result Inspect(Id id) => _client.Inspect(id);
  public string Example() => "throw new NotSupportedException()";
  public string RawExample() => """
    class FakeRaw {
      public void Run(string tenant, int region, bool active) { }
    }
    """;
}
class One {
  public void Run(string tenant, int region, bool active) { }
}
class Two {
  public void Run(int region, string tenant, bool active) { }
}
''',
      });

      expect(
        findings.where((finding) => csharpOopRuleIds.contains(finding.code)),
        isEmpty,
      );
    },
  );
}

List<Finding> _findings(Map<String, String> sources) {
  final CSharpOopProject project = CSharpOopProject.parse(sources);
  final RuleContext context = RuleContext(
    config: const AnalysisConfig(root: '.'),
    sources: sources,
    language: 'csharp',
    languageAnalysis: project,
  );
  return <Finding>[
    for (final String id in csharpOopRuleIds)
      ...CSharpOopRule(id).analyze(context),
  ];
}
