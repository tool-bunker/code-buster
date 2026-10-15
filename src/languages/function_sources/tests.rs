#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_nested_python_functions_with_their_own_scope() {
        let functions = extract(&BTreeMap::from([(
            "service.py".to_owned(),
            "def outer():\n    def inner():\n        return 1\n    return inner()\n\ndef after():\n    return 2\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line))
                .collect::<Vec<_>>(),
            [("outer", 1), ("inner", 2), ("after", 6)]
        );
    }

    #[test]
    fn preserves_multiline_python_signatures_and_body_scope() {
        let functions = extract(&BTreeMap::from([(
            "service.py".to_owned(),
            "def render(\n    name: str,\n    template: str = \")\",\n):\n    return name, template\n\ndef after():\n    return 2\n"
                .to_owned(),
        )]));

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "render");
        assert!(functions[0].source.contains("template: str"));
        assert!(functions[0].source.contains("return name, template"));
        assert_eq!(functions[1].name, "after");
    }

    #[test]
    fn ignores_python_function_examples_inside_docstrings() {
        let functions = extract(&BTreeMap::from([(
            "service.py".to_owned(),
            "\"\"\"Usage:\n    def phantom(alpha, beta, gamma, delta):\n        return alpha\n\"\"\"\n\ndef actual():\n    return 1\n"
                .to_owned(),
        )]));

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "actual");
        assert_eq!(functions[0].line, 6);
    }

    #[test]
    fn preserves_multiline_python_return_annotations() {
        let functions = extract(&BTreeMap::from([(
            "contracts.py".to_owned(),
            "def contract(\n    alpha: str,\n    beta: str,\n    gamma: str,\n    delta: str,\n) -> Result[\n    tuple[str, str, str, str]\n]: ...\n\ndef after():\n    return 1\n"
                .to_owned(),
        )]));

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "contract");
        assert!(functions[0].source.contains("]: ..."));
        assert_eq!(functions[1].name, "after");
    }

    #[test]
    fn normalizes_dart_functions_like_analyzer_ast_sources() {
        let functions = extract(&BTreeMap::from([(
            "lib/main.dart".to_owned(),
            "void nested() {\n  // control-flow prose: if\n  if (first) {\n    run();\n  }\n}\n"
                .to_owned(),
        )]));

        assert_eq!(functions.len(), 1);
        assert!(!functions[0].source.contains('\n'));
        assert!(!functions[0].source.contains("prose"));
        assert!(functions[0].source.contains("if (first)"));
    }

    #[test]
    fn extracts_dart_callables_without_string_or_closure_false_positives() {
        let functions = extract(&BTreeMap::from([(
            "lib/runner.dart".to_owned(),
            r#"
final example = '''
void phantom() {
  if (never) run();
}
''';

class Runner<T> {
  Runner.named({required this.value}) {
    initialize();
  }

  final T value;

  /// Executes work.
  static Future<(int, String)> execute({required int count}) async {
    final callback = () => count > 0 ? count : 0;
    if (count > 1) callback();
    return (count, '$value');
  }

  bool get ready => value != null;
}
"#
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["Runner.named", "execute", "ready"]
        );
        assert_eq!(functions[1].line, 15);
        assert!(functions[1].source.contains("callback"));
        assert!(!functions.iter().any(|function| function.name == "phantom"));
    }

    #[test]
    fn extracts_dart_operator_declarations_without_comparison_false_positives() {
        let functions = extract(&BTreeMap::from([(
            "lib/value.dart".to_owned(),
            r#"
class Value {
  @override
  bool operator ==(
    Object other,
  ) {
    if (identical(this, other)) return true;
    return other is Value && other.first == first && other.second == second;
  }

  bool matches(Object other) {
    if (first == other) return true;
    return false;
  }

  Future<({String? token, String? code})> authorize(Object other) async {
    return (token: null, code: null);
  }
}

(
  double? left,
  double? right,
) position(
  Object other,
) {
  return (left: null, right: null);
}
"#
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["==", "matches", "authorize", "position"]
        );
        assert_eq!(functions[0].line, 3);
    }

    #[test]
    fn ignores_dart_calls_before_named_collection_arguments() {
        let functions = extract(&BTreeMap::from([(
            "test/rules_test.dart".to_owned(),
            r#"
void fixture() {
  invoke(
    config: AnalysisConfig(
      root: '.',
      ruleGroups: <String>{'suspicious'},
    ),
    sources: <String, String>{},
  );
}
"#
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["fixture"]
        );
    }

    #[test]
    fn extracts_rust_functions_around_lifetimes_raw_strings_and_tests() {
        let functions = extract(&BTreeMap::from([(
            "src/lib.rs".to_owned(),
            "fn keep<'a>(value: &'a str) {\n  let sample = r#\"} fn fake() {\"#;\n  if value.is_empty() {}\n}\n\
             #[cfg(test)]\nfn skipped() {}\n\
             fn after() {}\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["keep", "after"]
        );
        assert_eq!(functions[0].end_line, 4);
    }
    #[test]
    fn extracts_go_functions_with_interface_parameters() {
        let functions = extract(&BTreeMap::from([(
            "command.go".to_owned(),
            "func defaultUsageFunc(w io.Writer, in interface{}) error {\n\
             \tif ready {\n\
             \t\treturn nil\n\
             \t}\n\
             \treturn nil\n\
             }\n\
             func after() {}\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line, function.end_line))
                .collect::<Vec<_>>(),
            [("defaultUsageFunc", 1, 6), ("after", 7, 7)]
        );
        assert!(functions[0].source.contains("interface{}"));
    }
    #[test]
    fn extracts_javascript_functions_with_destructured_and_typed_object_parameters() {
        let functions = extract(&BTreeMap::from([
            (
                "tool/meta.js".to_owned(),
                "function writeDocumentTitles({ englishDocs, translatedDocs }) {\n  if (englishDocs) return translatedDocs;\n}\n"
                    .to_owned(),
            ),
            (
                "web/snippet.tsx".to_owned(),
                "export function AutoSnippet(props: {\n  raw: string | Array<string>;\n  title?: string;\n}) {\n  if (props.raw) return props.title;\n}\n"
                    .to_owned(),
            ),
        ]));

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["writeDocumentTitles", "AutoSnippet"]
        );
        assert!(functions[0].source.contains("if (englishDocs)"));
        assert!(functions[1].source.contains("if (props.raw)"));
    }
    #[test]
    fn matches_javascript_anonymous_arrow_and_nested_function_boundaries() {
        let functions = extract(&BTreeMap::from([(
            "src/index.ts".to_owned(),
            "const named = () => { if (named) run(); };\n\
             export const exported = () => { if (exported) run(); };\n\
             const assigned = function (value) { if (value) run(); };\n\
             function outer() {\n\
               const nested = () => { if (nested) run(); };\n\
               if (outer) run();\n\
             }\n"
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line))
                .collect::<Vec<_>>(),
            [
                ("named", 1),
                ("<anonymous>", 2),
                ("<anonymous>", 3),
                ("outer", 4),
                ("nested", 5),
            ]
        );
        assert!(!functions[3].source.contains("if (nested)"));
        assert!(functions[3].source.contains("if (outer)"));
    }
    #[test]
    fn javascript_arrow_candidates_do_not_cross_statement_boundaries() {
        let functions = extract(&BTreeMap::from([(
            "src/client.ts".to_owned(),
            "function send() {\n\
               let error: any;\n\
               if (signal) {\n\
                 signal.onabort = () => {\n\
                   error = new Error();\n\
                 };\n\
               }\n\
             }\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line))
                .collect::<Vec<_>>(),
            [("send", 1), ("<anonymous>", 4)]
        );
        assert!(functions[0].source.contains("if (signal)"));
        assert!(!functions[0].source.contains("new Error"));
    }

    #[test]
    fn javascript_function_boundaries_ignore_masked_braces() {
        let functions = extract(&BTreeMap::from([(
            "src/masked.js".to_owned(),
            "function real() {\n  const pattern = /[{}]\\/value/g;\n  const text = \"}\";\n  // }\n  /* { */\n  if (ready) {}\n}\nfunction after() {}\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line, function.end_line))
                .collect::<Vec<_>>(),
            [("real", 1, 7), ("after", 8, 8)]
        );
    }

    #[test]
    fn preserves_nested_multiline_interpolations_like_dart_to_source() {
        let functions = extract(&BTreeMap::from([(
            "lib/generator.dart".to_owned(),
            r####"
String generate(bool empty) {
  return '''
${empty ? 'none' : '''
while (next()) {
  switch (key) {}
}
'''}
''';
}
"####
                .to_owned(),
        )]));

        assert_eq!(functions.len(), 1);
        assert!(functions[0].source.contains(": '''\nwhile (next()) {"));
        assert!(functions[0].source.contains("\n'''}\n'''"));
    }
    #[test]
    fn java_extraction_skips_nested_anonymous_class_methods() {
        let functions = extract(&BTreeMap::from([(
            "Example.java".to_owned(),
            "class Example {\n\
               void outer() {\n\
                 callbacks.add(new Callback() {\n\
                   public void nested() { if (ready) run(); }\n\
                 });\n\
               }\n\
               void after() { while (ready) run(); }\n\
             }\n"
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line, function.end_line))
                .collect::<Vec<_>>(),
            [("outer", 2, 6), ("after", 7, 7)]
        );
    }

    #[test]
    fn csharp_extraction_handles_tuple_returns_and_multiline_signatures() {
        let functions = extract(&BTreeMap::from([(
            "Parser.cs".to_owned(),
            "class Parser\n\
             {\n\
               private static (Style Style, Link? Link)? Parse(string text, out string? error)\n\
               {\n\
                 return default;\n\
               }\n\
               public static bool TryParse(\n\
                 string text)\n\
               {\n\
                 return true;\n\
               }\n\
             }\n"
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line, function.end_line))
                .collect::<Vec<_>>(),
            [("Parse", 3, 6), ("TryParse", 7, 11)]
        );
    }
    #[test]
    fn csharp_extraction_uses_the_declaration_name_around_nested_calls() {
        let functions = extract(&BTreeMap::from([(
            "Example.cs".to_owned(),
            "class Example {\n\
               [DynamicDependency(JsonSerialized, typeof(Node))]\n\
               public Result DeserializeParameters(Input input) {\n\
                 if (input != null) return default;\n\
               }\n\
               public Example(Input input)\n\
                 : base(input)\n\
               {\n\
                 if (input == null) throw new Error();\n\
               }\n\
               private unsafe void FlushInternal(bool end, ArraySegment<byte> data = new ArraySegment<byte>())\n\
               {\n\
                 if (end) return;\n\
               }\n\
             }\n"
                .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line))
                .collect::<Vec<_>>(),
            [
                ("DeserializeParameters", 2),
                ("Example", 6),
                ("FlushInternal", 11),
            ]
        );
    }

    #[test]
    fn cpp_extraction_separates_nested_lambdas_from_the_owner() {
        let functions = extract(&BTreeMap::from([(
            "worker.cpp".to_owned(),
            "int outer(int value) {\n\
               auto transform = [value](int item) { if (item > value) return item; return value; };\n\
               if (value > 0) return transform(value);\n\
               return 0;\n\
             }\n"
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line))
                .collect::<Vec<_>>(),
            [("outer", 1), ("<lambda>", 2)]
        );
        assert!(!functions[0].source.contains("item > value"));
        assert!(functions[1].source.contains("item > value"));
    }

    #[test]
    fn cpp_extraction_ignores_inactive_and_stringified_functions() {
        let functions = extract(&BTreeMap::from([(
            "worker.c".to_owned(),
            "#define STRINGIFY_IMPL(value) #value\n\
             #define STRINGIFY(value) STRINGIFY_IMPL(value)\n\
             const char* text = STRINGIFY(int fake() { if (never) return 1; });\n\
             #if 0\n\
             int inactive() { if (never) return 1; }\n\
             #endif\n\
             int active(\n\
               int value)\n\
             {\n\
               return value;\n\
             }\n"
            .to_owned(),
        )]));

        assert_eq!(
            functions
                .iter()
                .map(|function| (function.name.as_str(), function.line, function.end_line))
                .collect::<Vec<_>>(),
            [("active", 7, 11)]
        );
    }

}
