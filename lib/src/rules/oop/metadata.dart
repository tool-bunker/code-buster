import '../../core/models.dart';

final Map<String, RuleMetadata> _metadata = <String, RuleMetadata>{
  'oop-data-clump': const RuleMetadata(
    id: 'oop-data-clump',
    version: 4,
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Group a repeated parameter concept',
    why:
        'The same typed parameter group crossing several APIs usually represents one domain concept whose validation and evolution are otherwise distributed.',
    suggestion:
        'Consider a value object or parameter object if these values share invariants and lifecycle.',
    semanticMaturity: RuleSemanticMaturity.project,
    requirements: <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.declarations,
    },
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart', 'csharp', 'java', 'javascript', 'typescript'],
    limitations: <String>[
      'Requires the same complete signature of at least three explicitly typed parameters in three declarations across at least two files.',
      'Parameter names and normalized types must match; inferred parameters and partial parameter subsets are not analyzed.',
      'TypeScript destructured, inferred, and nested generic parameters are not analyzed.',
      'C# partial types, aliases, and generic parameter splitting are not resolved.',
    ],
  ),
  'oop-interface-segregation-pressure': const RuleMetadata(
    id: 'oop-interface-segregation-pressure',
    version: 4,
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Split a contract implementations cannot fully support',
    why:
        'Several implementations rejecting different interface operations indicates that clients depend on a contract broader than those implementations can honor.',
    suggestion:
        'Consider capability-specific interfaces or composition so each implementation exposes only supported operations.',
    semanticMaturity: RuleSemanticMaturity.project,
    requirements: <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.declarations,
    },
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart', 'csharp', 'java', 'javascript', 'typescript'],
    limitations: <String>[
      'Requires a contract with at least four methods and at least two direct implementors.',
      'At least two implementors must explicitly reject contract methods, with three rejected implementations across two operations.',
      'Inherited implementations, partial types, mixins, and indirect interface inheritance are not resolved.',
    ],
  ),
  'oop-refused-bequest': const RuleMetadata(
    id: 'oop-refused-bequest',
    version: 4,
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Narrow an inheritance contract subclasses reject',
    why:
        'Several subclasses rejecting inherited operations indicates that the base class promises behavior those subtypes cannot honor.',
    suggestion:
        'Consider composition or smaller capability-specific base contracts so subclasses inherit only supported behavior.',
    semanticMaturity: RuleSemanticMaturity.project,
    requirements: <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.declarations,
    },
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart', 'csharp', 'java', 'javascript', 'typescript'],
    limitations: <String>[
      'Requires a directly declared base class with at least four instance methods and at least two direct subclasses.',
      'Each qualifying subclass must override and explicitly reject at least two inherited methods; at least three distinct operations must be rejected.',
      'Indirect inheritance, partial types, mixins, and resolved overrides are not analyzed.',
    ],
  ),
  'oop-middle-man-delegation': const RuleMetadata(
    id: 'oop-middle-man-delegation',
    version: 4,
    defaultSeverity: RuleSeverity.info,
    group: 'maintainability',
    title: 'Review a predominantly forwarding class',
    why:
        'A class whose public API mostly forwards unchanged operations adds navigation and maintenance without clearly owning policy.',
    suggestion:
        'Consider exposing the collaborator directly or moving real policy into the boundary; retain the wrapper when it intentionally isolates an external contract.',
    semanticMaturity: RuleSemanticMaturity.project,
    requirements: <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.declarations,
    },
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
    languages: <String>['dart', 'csharp', 'java', 'javascript', 'typescript'],
    limitations: <String>[
      'Requires at least five public instance methods, with at least four and eighty percent directly forwarding to the same private typed field.',
      'Forwarded methods must call the same method name with unchanged parameters using an expression body or one statement.',
      'Classes with inheritance or implemented contracts are excluded because proxy, adapter, and framework boundaries may require forwarding.',
    ],
  ),
  'oop-repeated-strategy-dispatch': _advisory(
    'oop-repeated-strategy-dispatch',
    'Consolidate repeated variant dispatch',
    'Repeated switches over the same variants distribute strategy selection.',
    'Consider variant-owned behavior or one strategy boundary.',
    'Requires three switches over at least three identical variants across two files.',
  ),
  'oop-state-behavior-candidate': _advisory(
    'oop-state-behavior-candidate',
    'Centralize repeated state-dependent behavior',
    'Repeated switches on mutable state distribute lifecycle behavior.',
    'Consider state-owned behavior or one transition boundary.',
    'Requires three methods switching over one field and at least three states.',
  ),
  'oop-feature-envy': _advisory(
    'oop-feature-envy',
    'Keep behavior with the data it uses',
    'A method dominated by one parameter’s members may own misplaced behavior.',
    'Consider moving the behavior to the foreign type or its API.',
    'Requires five accesses across three members and sixty percent of received accesses.',
  ),
  'oop-service-locator-dependency': _advisory(
    'oop-service-locator-dependency',
    'Make distributed service dependencies explicit',
    'Shared locator access hides collaborators and couples behavior to global state.',
    'Consider constructor injection at the application boundary.',
    'Requires three classes across two files resolving three service types from one conventionally named locator.',
  ),
  'oop-repeated-observer-notification': _advisory(
    'oop-repeated-observer-notification',
    'Centralize repeated observer notification',
    'Repeated observer traversal distributes notification ordering and failure policy.',
    'Consider one notification boundary or event dispatcher.',
    'Requires add/remove registration symmetry and the same callback loop in three methods.',
  ),
  'oop-message-chain': _advisory(
    'oop-message-chain',
    'Hide repeated deep collaboration chains',
    'Deep navigation couples a class to an entire collaborator graph.',
    'Consider a higher-level query or narrow facade.',
    'Requires three chains of at least four hops across two methods.',
  ),
  for (final role in <String>['factory', 'facade', 'repository', 'proxy'])
    'oop-$role-bypass': _advisory(
      'oop-$role-bypass',
      'Do not bypass an established $role',
      'A dominant boundary loses policy ownership when callers access its implementations directly.',
      'Route direct access through the established boundary.',
      'Requires three external boundary users and dominant use over direct implementation access.',
    ),
  'oop-repeated-adapter-mapping': _advisory(
    'oop-repeated-adapter-mapping',
    'Centralize a repeated object translation boundary',
    'Repeated source-to-target mappings distribute compatibility policy.',
    'Consider one mapper or target factory.',
    'Requires three identical mappings of at least three members across two files.',
  ),
  'oop-template-workflow-candidate': _advisory(
    'oop-template-workflow-candidate',
    'Share a stable sibling workflow',
    'Sibling overrides repeating an ordered workflow duplicate invariant behavior.',
    'Consider a shared workflow with one varying step.',
    'Requires sibling overrides with four to ten calls and exactly one differing call.',
  ),
};

const Set<String> _sharedLexicalOopIds = <String>{
  'oop-repeated-strategy-dispatch',
  'oop-state-behavior-candidate',
  'oop-feature-envy',
  'oop-message-chain',
  'oop-service-locator-dependency',
  'oop-repeated-observer-notification',
  'oop-factory-bypass',
  'oop-facade-bypass',
  'oop-repository-bypass',
  'oop-proxy-bypass',
  'oop-repeated-adapter-mapping',
  'oop-template-workflow-candidate',
};

RuleMetadata _advisory(
  String id,
  String title,
  String why,
  String suggestion,
  String limitation,
) => RuleMetadata(
  id: id,
  defaultSeverity: RuleSeverity.info,
  group: 'maintainability',
  title: title,
  why: why,
  suggestion: suggestion,
  version: id == 'oop-template-workflow-candidate'
      ? 5
      : _sharedLexicalOopIds.contains(id)
      ? 4
      : 1,
  semanticMaturity: RuleSemanticMaturity.project,
  requirements: const <RuleAnalysisRequirement>{
    RuleAnalysisRequirement.declarations,
  },
  taxonomy: const <FindingTaxonomy>{FindingTaxonomy.maintainability},
  languages: <String>[
    'dart',
    'csharp',
    if (_sharedLexicalOopIds.contains(id)) 'java',
    if (_sharedLexicalOopIds.contains(id)) 'javascript',
    if (_sharedLexicalOopIds.contains(id)) 'typescript',
  ],
  limitations: <String>[
    limitation,
    'Comments, strings, generated, test, example, and vendored sources follow normal analysis classification and suppression controls.',
  ],
);

RuleMetadata oopRuleMetadata(String id) {
  final RuleMetadata? metadata = _metadata[id];
  if (metadata == null) {
    throw ArgumentError.value(id, 'id', 'unknown shared OOP rule');
  }
  return metadata;
}
