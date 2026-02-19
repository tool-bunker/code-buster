// Tests and bundled tooling need implementation access without promising those symbols as part of the package’s public API.

/// Unstable implementation surface used by Code Buster's executable and tests.
///
/// External packages must import `package:code_buster/code_buster.dart`
/// instead. Declarations exported here may move without a compatibility period.
library;

export 'cache/analysis_cache.dart';
export 'catalog/canonical_rule_descriptors.dart';
export 'catalog/rule_catalog.dart';
export 'cli/cli_contract.dart';
export 'config/config.dart';
export 'config/repository_defaults.dart';
export 'controls/finding_controls.dart';
export 'core/models.dart';
export 'core/processing_diagnostic.dart';
export 'core/rule.dart';
export 'core/rule_policy.dart';
export 'core/run_manifest.dart';
export 'core/schema_versions.dart';
export 'discovery/discovery.dart';
export 'discovery/language_versions.dart';
export 'engine/analysis.dart';
export 'engine/analysis_pipeline.dart';
export 'engine/analysis_runner.dart';
export 'engine/rule_execution.dart';
export 'fixes/fixer.dart';
export 'graph/graph.dart';
export 'ingestion/sarif_ingestion.dart';
export 'languages/cpp/cpp_adapter.dart';
export 'languages/csharp/csharp_adapter.dart';
export 'languages/dart/dart_adapter.dart';
export 'languages/go/go_adapter.dart';
export 'languages/java/java_adapter.dart';
export 'languages/javascript/javascript_adapter.dart';
export 'languages/lua/lua_adapter.dart';
export 'languages/nim/nim_adapter.dart';
export 'languages/python/python_adapter.dart';
export 'languages/wren/wren_adapter.dart';
export 'plugins/language_plugin.dart';
export 'plugins/languages.dart';
export 'reporting/reporting.dart';
