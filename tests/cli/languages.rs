#[test]
fn omitted_command_defaults_to_summary() {
    let root = TempDirectory::new("cbr-default-summary");
    root.write("lib/main.dart", b"void main() {}\n");

    let output = run(&["--root", root.path.to_str().unwrap(), "--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("default command must emit summary JSON");
    assert_eq!(report["command"], "summary");
}

#[test]
fn summary_reports_the_mixed_language_contract() {
    let root = TempDirectory::new("cbr-mixed-language");
    root.write(
        "code-buster.toml",
        b"languages = [\"dart\", \"python\", \"typescript\", \"cpp\", \"sql\", \"wren\"]\n\
          [files]\n\
          entry_points = [\"lib/main.dart\", \"python/main.py\", \"web/main.ts\", \"native/main.cpp\", \"wren/main.wren\"]\n\
          [rules]\n\
          enabled_groups = [\"core\", \"nim-style\", \"sql\"]\n\
          [rules.severity]\n\
          dart-print = \"info\"\n\
          py-requests-timeout = \"warn\"\n\
          ts-console = \"info\"\n\
          cpp-malloc-free = \"warn\"\n\
          sql-delete-without-where = \"warn\"\n\
          wren-number-parse-unchecked = \"info\"\n",
    );
    root.write("db/migrate.sql", b"DELETE FROM expired_sessions;\n");
    root.write("lib/main.dart", b"void main() {\n  print('ready');\n}\n");
    root.write(
        "native/main.cpp",
        b"#include <cstdlib>\nint main() {\n  void* value = malloc(4);\n  free(value);\n  return 0;\n}\n",
    );
    root.write(
        "python/main.py",
        b"import requests\n\ndef load():\n    return requests.get(\"https://example.test\")\n",
    );
    root.write(
        "web/main.ts",
        b"export function start(): void {\n  console.log(\"ready\");\n}\n",
    );
    root.write(
        "wren/main.wren",
        b"class Main {\n  parse(value) {\n    return Num.fromString(value)\n  }\n}\n",
    );

    let output = run_summary(&root.path, &["--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(
        findings
            .iter()
            .map(|finding| (
                finding["code"].as_str().unwrap(),
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
            .collect::<Vec<_>>(),
        vec![
            ("sql-delete-without-where", "db/migrate.sql", 1, 1),
            ("dart-print", "lib/main.dart", 2, 2),
            ("cpp-malloc-free", "native/main.cpp", 3, 0),
            ("cpp-malloc-free", "native/main.cpp", 4, 0),
            ("py-requests-timeout", "python/main.py", 4, 4),
            ("ts-console", "web/main.ts", 2, 2),
            ("wren-number-parse-unchecked", "wren/main.wren", 3, 3,),
        ]
    );
    let python = findings
        .iter()
        .find(|finding| finding["code"] == "py-requests-timeout")
        .unwrap();
    assert_eq!(python["security_kind"], "hotspot");
}

#[test]
fn summary_reports_complete_wren_and_sql_rule_families() {
    let root = TempDirectory::new("cbr-wren-sql");
    root.write(
        "code-buster.toml",
        b"languages = [\"wren\", \"sql\"]\n[files]\nentry_points = [\"wren/main.wren\"]\n",
    );
    root.write(
        "db/migration.sql",
        b"SELECT * FROM users WHERE name LIKE '%bob';\n\
          DELETE FROM sessions;\n\
          UPDATE accounts SET active = false;\n\
          DROP TABLE audit;\n\
          CREATE INDEX idx_users_name ON users(name);\n\
          ALTER TABLE users ADD COLUMN enabled boolean NOT NULL DEFAULT true;\n\
          SELECT id FROM users WHERE id NOT IN (SELECT user_id FROM bans);\n",
    );
    root.write(
        "wren/main.wren",
        b"import \"module\" for A, B, C, D, E, F, G, H, I\n\
          class Main is Base {\n\
            foreign static nativeCall()\n\
            run(fiber) {\n\
              while (true) {\n\
                System.print(\"tick\")\n\
                System.write(\".\")\n\
              }\n\
              fiber.call()\n\
              var value = Num.fromString(input)\n\
              Fiber.abort(\"stop\")\n\
            }\n\
          }\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            (code.starts_with("sql-") || code.starts_with("wren-")).then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["confidence"].as_str().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        vec![
            ("sql-select-star", "db/migration.sql", 1, "low"),
            ("sql-case-sensitive-like", "db/migration.sql", 1, "low"),
            ("sql-leading-wildcard-like", "db/migration.sql", 1, "low"),
            ("sql-delete-without-where", "db/migration.sql", 2, "medium"),
            ("sql-update-without-where", "db/migration.sql", 3, "medium"),
            (
                "sql-drop-table-without-if-exists",
                "db/migration.sql",
                4,
                "low",
            ),
            (
                "sql-create-index-nonconcurrent",
                "db/migration.sql",
                5,
                "low",
            ),
            ("sql-add-not-null-default", "db/migration.sql", 6, "medium",),
            (
                "sql-not-in-subquery-null-risk",
                "db/migration.sql",
                7,
                "low",
            ),
            ("wren-broad-import", "wren/main.wren", 1, "medium"),
            ("wren-inheritance", "wren/main.wren", 2, "medium"),
            ("wren-foreign-boundary", "wren/main.wren", 3, "medium"),
            ("wren-system-print", "wren/main.wren", 6, "medium"),
            ("wren-print-in-loop", "wren/main.wren", 6, "medium"),
            ("wren-print-in-loop", "wren/main.wren", 7, "medium"),
            ("wren-fiber-call", "wren/main.wren", 9, "medium"),
            (
                "wren-number-parse-unchecked",
                "wren/main.wren",
                10,
                "medium",
            ),
            ("wren-fiber-abort", "wren/main.wren", 11, "medium"),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
}

#[test]
fn summary_reports_complete_cpp_rule_family() {
    let root = TempDirectory::new("cbr-cpp");
    root.write(
        "code-buster.toml",
        b"languages = [\"cpp\"]\n\
          [files]\n\
          entry_points = [\"main.cpp\"]\n\
          [rules]\n\
          enabled_groups = [\"nim-style\"]\n",
    );
    root.write(
        "main.cpp",
        b"using namespace std;\n\
          #define BUFFER_SIZE 4096\n\
          class Interface {\n\
           public:\n\
            virtual void draw();\n\
          };\n\
          void mutate(int& value) {\n\
            int converted = (int)value;\n\
            void* memory = malloc(16);\n\
            strcpy((char*)memory, input);\n\
            memset(memory, 0, 16);\n\
            auto random = rand();\n\
            auto immutable = const_cast<int*>(source);\n\
            auto raw = reinterpret_cast<char*>(memory);\n\
            Widget* widget = new Widget();\n\
            delete widget;\n\
            if (memory == NULL) goto cleanup;\n\
          cleanup: free(memory);\n\
          }\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            code.starts_with("cpp-").then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        vec![
            ("cpp-using-namespace-std", "main.cpp", 1, 0),
            ("cpp-macro-constant", "main.cpp", 2, 0),
            ("cpp-virtual-no-destructor", "main.cpp", 3, 0),
            ("cpp-non-const-ref-param", "main.cpp", 7, 0),
            ("cpp-cast", "main.cpp", 8, 0),
            ("cpp-malloc-free", "main.cpp", 9, 0),
            ("cpp-cast", "main.cpp", 10, 0),
            ("cpp-unsafe-c-string", "main.cpp", 10, 0),
            ("cpp-memset-zero", "main.cpp", 11, 0),
            ("cpp-rand", "main.cpp", 12, 0),
            ("cpp-const-cast", "main.cpp", 13, 0),
            ("cpp-reinterpret-cast", "main.cpp", 14, 0),
            ("cpp-raw-owning-new", "main.cpp", 15, 0),
            ("cpp-manual-delete", "main.cpp", 16, 0),
            ("cpp-null", "main.cpp", 17, 0),
            ("cpp-goto", "main.cpp", 17, 0),
            ("cpp-malloc-free", "main.cpp", 18, 0),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
}

#[test]
fn summary_reports_complete_python_rule_family() {
    let root = TempDirectory::new("cbr-python");
    root.write(
        "code-buster.toml",
        b"languages = [\"python\"]\n[files]\nentry_points = [\"app.py\"]\n",
    );
    root.write(
        "app.py",
        b"import os, sys\n\
          from module import *\n\
          value = eval(input())\n\
          import late\n\
          def BadName(items=[]):\n\
              assert items\n\
              requests.get(url, verify=False)\n\
          async def load():\n\
          \x20\x20\x20\x20time.sleep(1)\n\
          password = \"real-secret-value\"\n\
          data = yaml.load(payload)\n\
          query = f\"SELECT * FROM users WHERE id = {value}\"\n\
          handle = open(\"data.txt\")\n\
          tempfile.mktemp()\n\
          if ready: run()\n\
          values = call( value )\n\
          total = first + \\\n+              second\n\
          try:\n\
              run()\n\
          except Exception:\n\
              print(error)\n\
          except:\n\
              pass\n\
          pickle.load(stream)\n\
          hashlib.md5(data)\n\
          debug = True\n\
          subprocess.run(command, shell=True)\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            code.starts_with("py-").then_some((
                code,
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        vec![
            ("py-multiple-imports", 1, 1),
            ("py-wildcard-import", 2, 2),
            ("py-eval-exec", 3, 3),
            ("py-import-not-top", 4, 4),
            ("py-function-naming", 5, 5),
            ("py-mutable-default", 5, 5),
            ("py-assert-runtime", 6, 6),
            ("py-requests-timeout", 7, 7),
            ("py-insecure-tls", 7, 7),
            ("py-async-blocking-call", 9, 9),
            ("py-hardcoded-secret", 10, 10),
            ("py-yaml-load", 11, 11),
            ("py-sql-string-build", 12, 12),
            ("py-open-no-encoding", 13, 13),
            ("py-tempfile-mktemp", 14, 14),
            ("py-compound-statement", 15, 15),
            ("py-extraneous-whitespace", 16, 16),
            ("py-backslash-continuation", 17, 17),
            ("py-broad-except", 21, 21),
            ("py-logging-exception", 22, 22),
            ("py-bare-except", 23, 23),
            ("py-pickle", 25, 25),
            ("py-weak-hash", 26, 26),
            ("py-debug-enabled", 27, 27),
            ("py-subprocess-shell", 28, 28),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
}

#[test]
fn summary_honors_python_project_lint_suppressions() {
    let root = TempDirectory::new("cbr-python-policy");
    root.write(
        "app.py",
        b"value = 1\n\
          import late\n\
          def CamelCase(values=[]):\n\
              try:\n\
                  return values\n\
              except Exception:\n\
                  return []\n\
              except:\n\
                  return None\n",
    );
    root.write(
        "pyproject.toml",
        b"[tool.pylint.messages_control]\n\
          disable = [\"invalid-name\", \"dangerous-default-value\", \"broad-exception-caught\"]\n\
          [tool.ruff.lint]\n\
          ignore = [\"E402\", \"E722\"]\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| {
                !finding["code"]
                    .as_str()
                    .is_some_and(|code| code.starts_with("py-"))
            })
    );
}

#[test]
fn summary_reports_complete_java_rule_family() {
    let root = TempDirectory::new("cbr-java");
    root.write(
        "code-buster.toml",
        b"languages = [\"java\"]\n[files]\nentry_points = [\"Main.java\"]\n",
    );
    root.write(
        "Main.java",
        b"class Main {\n\
          void run(int a, int b, int c, int d, int e, int f, int g, int h) {\n\
          String password = \"real-secret-value\";\n\
          ObjectInputStream input = open();\n\
          FileInputStream file = new FileInputStream(path);\n\
          String text = \"\";\n\
          for (String value : values) { text += value; }\n\
          if (text == \"ready\") System.out.println(text);\n\
          Thread.sleep(1);\n\
          error.printStackTrace();\n\
          Random tokenRandom = new Random();\n\
          String query = \"SELECT * FROM users WHERE id=\" + id;\n\
          Cipher.getInstance(\"DES\");\n\
          try { work(); } catch (Exception error) {}\n\
          }\n\
          }\n",
    );
    root.write(
        "src/a/A.java",
        b"package app.a;\nimport app.b.B;\nclass A { B value; }\n",
    );
    root.write(
        "src/b/B.java",
        b"package app.b;\nimport app.a.A;\nclass B { A value; }\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            code.starts_with("java-").then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings,
        vec![
            ("java-too-many-parameters", "Main.java", 2, 0),
            ("java-hardcoded-secret", "Main.java", 3, 0),
            ("java-objectinputstream", "Main.java", 4, 0),
            ("java-resource-not-closed", "Main.java", 5, 0),
            ("java-string-concat-in-loop", "Main.java", 7, 0),
            ("java-string-equals", "Main.java", 8, 0),
            ("java-system-out", "Main.java", 8, 0),
            ("java-thread-sleep", "Main.java", 9, 0),
            ("java-print-stacktrace", "Main.java", 10, 0),
            ("java-random-security", "Main.java", 11, 0),
            ("java-sql-string-build", "Main.java", 12, 0),
            ("java-weak-crypto", "Main.java", 13, 0),
            ("java-catch-exception", "Main.java", 14, 0),
            ("java-empty-catch", "Main.java", 14, 0),
            ("java-package-cycle", "app/a", 1, 0),
        ]
    );
}

#[test]
fn summary_reports_complete_javascript_and_typescript_rule_family() {
    let root = TempDirectory::new("cbr-typescript");
    root.write(
        "code-buster.toml",
        b"languages = [\"typescript\"]\n[files]\nentry_points = [\"main.ts\"]\n",
    );
    root.write(
        "main.ts",
        b"import { R_OK, W_OK } from 'node:fs';\n\
          const value: any = JSON.parse(input);\n\
          console.log(value);\n\
          debugger;\n\
          eval(input);\n\
          element.innerHTML = input;\n\
          fetch('/api');\n\
          const password = \"secret\";\n\
          for (const item of items) {\n\
          await save(item);\n\
          }\n\
          const definite = value!.name;\n\
          const cached = JSON.parse(localStorage.value);\n\
          setTimeout(\"runTask()\", 10);\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            (code.starts_with("ts-") || code == "js-node-fs-constant-import").then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings,
        vec![
            ("js-node-fs-constant-import", "main.ts", 1, 0),
            ("ts-any", "main.ts", 2, 2),
            ("ts-json-parse-unsafe", "main.ts", 2, 2),
            ("ts-console", "main.ts", 3, 3),
            ("ts-debugger", "main.ts", 4, 4),
            ("ts-eval", "main.ts", 5, 5),
            ("ts-inner-html", "main.ts", 6, 6),
            ("ts-floating-promise", "main.ts", 7, 7),
            ("ts-hardcoded-secret", "main.ts", 8, 8),
            ("ts-await-in-loop", "main.ts", 10, 10),
            ("ts-non-null-assertion", "main.ts", 12, 12),
            ("ts-json-parse-unsafe", "main.ts", 13, 13),
            ("ts-localstorage-json", "main.ts", 13, 13),
            ("ts-string-timer-code-execution", "main.ts", 14, 14),
        ]
    );
}

#[test]
fn summary_reports_complete_lua_rule_family() {
    let root = TempDirectory::new("cbr-lua");
    root.write(
        "code-buster.toml",
        b"languages = [\"lua\"]\n[files]\nentry_points = [\"main.lua\"]\n",
    );
    root.write(
        "main.lua",
        b"value = 1\n\
          function update()\n\
          print(\"frame\")\n\
          local state = {}\n\
          end\n\
          os.execute(\"echo unsafe\")\n\
          loadstring(\"return 1\")\n\
          pcall(work)\n\
          return\n\
          local values = {}\n\
          for key in pairs(values) do\n\
          values[key] = nil\n\
          end\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            code.starts_with("lua-").then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings,
        vec![
            ("lua-global-assignment", "main.lua", 1, 1),
            ("lua-print-in-loop", "main.lua", 3, 3),
            ("lua-table-alloc-in-loop", "main.lua", 4, 4),
            ("lua-os-execute", "main.lua", 6, 6),
            ("lua-loadstring", "main.lua", 7, 7),
            ("lua-pcall-swallow", "main.lua", 8, 8),
            ("lua-mutate-pairs", "main.lua", 11, 11),
        ]
    );
}

#[test]
fn summary_reports_complete_csharp_rule_family() {
    let root = TempDirectory::new("cbr-csharp");
    root.write(
        "code-buster.toml",
        b"languages = [\"csharp\"]\n[files]\nentry_points = [\"All.cs\", \"Archive.cs\"]\n",
    );
    root.write(
        ".editorconfig",
        b"csharp_style_namespace_declarations = file_scoped:warning\n",
    );
    root.write(
        "All.cs",
        b"namespace Demo {\n\
          using System.Text;\n\
          public class All {\n\
          [AllowPartiallyTrustedCallers]\n\
          [DllImport(\"native\")]\n\
          public static extern void Native();\n\
          async void Run(Task<int> task) {\n\
          string text = \"\";\n\
          for (;;) {\n\
          text = text + value;\n\
          }\n\
          try {}\n\
          catch (System.Exception error)\n\
          {\n\
          }\n\
          var formatter = new BinaryFormatter();\n\
          PermissionSet permission = Load();\n\
          System.Int32 count = 0;\n\
          if (ready & enabled) {}\n\
          var callback = new delegate();\n\
          var result = task.Result;\n\
          Thread.Sleep(1);\n\
          var now = DateTime.Now;\n\
          using var client = new HttpClient();\n\
          Process.Start(Request.Path);\n\
          var password = \"literal-secret\";\n\
          var random_password_value = new Random();\n\
          var userQuery = $\"SELECT * FROM Users WHERE Name = '{userName}'\";\n\
          var cipher = DES.Create();\n\
          var remote = RemotingConfiguration.ApplicationName;\n\
          var com = new ServicedComponent();\n\
          }\n\
          }\n",
    );
    root.write(
        "Archive.cs",
        b"class Archive {\n\
          void Extract(ZipArchiveEntry entry, string root) {\n\
          entry.ExtractToFile(Path.Combine(root, entry.FullName), true);\n\
          }\n\
          }\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--all-findings"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| {
            let code = finding["code"].as_str().unwrap();
            code.starts_with("cs-").then_some((
                code,
                finding["path"].as_str().unwrap(),
                finding["line"].as_u64().unwrap(),
                finding["end_line"].as_u64().unwrap(),
            ))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        findings,
        vec![
            ("cs-file-scoped-namespace", "All.cs", 1, 1),
            ("cs-using-inside-namespace", "All.cs", 2, 2),
            ("cs-aptca-attribute", "All.cs", 4, 4),
            ("cs-public-pinvoke", "All.cs", 5, 5),
            ("cs-async-void", "All.cs", 7, 7),
            ("cs-string-concat-loop", "All.cs", 10, 10),
            ("cs-catch-system-exception", "All.cs", 13, 13),
            ("cs-empty-catch", "All.cs", 13, 13),
            ("cs-binaryformatter", "All.cs", 16, 16),
            ("cs-cas-api", "All.cs", 17, 17),
            ("cs-runtime-type-alias", "All.cs", 18, 18),
            ("cs-non-short-circuit-bool", "All.cs", 19, 19),
            ("cs-explicit-delegate-new", "All.cs", 20, 20),
            ("cs-sync-over-async", "All.cs", 21, 21),
            ("cs-thread-sleep", "All.cs", 22, 22),
            ("cs-datetime-now", "All.cs", 23, 23),
            ("cs-new-httpclient", "All.cs", 24, 24),
            ("cs-process-start-input", "All.cs", 25, 25),
            ("cs-hardcoded-secret", "All.cs", 26, 26),
            ("cs-random-security", "All.cs", 27, 27),
            ("cs-sql-string-build", "All.cs", 28, 28),
            ("cs-weak-crypto", "All.cs", 29, 29),
            ("cs-remoting-api", "All.cs", 30, 30),
            ("cs-dcom-api", "All.cs", 31, 31),
            ("cs-archive-path-traversal", "Archive.cs", 3, 3),
        ]
    );
}

#[test]
fn unsupported_config_files_formats_fail() {
    let output = run(&["config", "--files", "--format", "markdown"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr must be UTF-8")
            .contains("config --files supports text and json formats")
    );
}

#[test]
fn summary_reports_project_wide_typescript_oop_findings() {
    let root = TempDirectory::new("cbr-oop-typescript");
    root.write(
        "first.ts",
        br#"export function createOrder(
  tenant: string,
  region: number,
  active: boolean,
): void {}
class Service {
  update(tenant: string, region: number, active: boolean): void {}
}
"#,
    );
    root.write(
        "second.ts",
        br#"interface Gateway {
  send(tenant: string, region: number, active: boolean): void;
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let oop_findings = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| {
            finding["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("oop-"))
        })
        .collect::<Vec<_>>();

    assert_eq!(oop_findings.len(), 1);
    assert_eq!(oop_findings[0]["code"], "oop-data-clump");
    assert_eq!(oop_findings[0]["path"], "first.ts");
    assert_eq!(
        oop_findings[0]["related_files"],
        serde_json::json!(["second.ts"])
    );
}

#[test]
fn summary_reports_project_wide_dart_oop_findings() {
    let root = TempDirectory::new("cbr-oop-dart");
    root.write(
        "lib/first.dart",
        br#"void createAddress(String street, String city, String postalCode) {}
void validateAddress(String postalCode, String street, String city) {}
"#,
    );
    root.write(
        "lib/second.dart",
        b"void updateAddress(String street, String city, String postalCode) {}\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let oop_findings = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| {
            finding["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("oop-"))
        })
        .collect::<Vec<_>>();

    assert_eq!(oop_findings.len(), 1);
    assert_eq!(oop_findings[0]["code"], "oop-data-clump");
    assert_eq!(oop_findings[0]["path"], "lib/first.dart");
    assert_eq!(
        oop_findings[0]["message"],
        "Parameters city, postalCode, street recur together in 3 declarations across 2 files"
    );
    assert_eq!(
        oop_findings[0]["related_files"],
        serde_json::json!(["lib/second.dart"])
    );
}

#[test]
fn summary_reports_nim_rule_family() {
    let root = TempDirectory::new("cbr-nim");
    root.write(
        "code-buster.toml",
        b"languages = [\"nim\"]\n[files]\nentry_points = [\"src/main.nim\"]\n",
    );
    root.write(
        "src/main.nim",
        b"import os\nproc risky*(a, b, c, d, e, f: int) =\n  var value = 1\n  return value\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let nim_codes = findings
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("nim-"))
        .collect::<Vec<_>>();

    assert_eq!(
        nim_codes,
        [
            "nim-no-test-suite",
            "nim-missing-raises",
            "nim-missing-doc",
            "nim-too-many-parameters",
            "nim-return-instead-of-result",
            "nim-std-import",
            "nim-prefer-let",
        ]
    );
    let standard_import = findings
        .iter()
        .find(|finding| finding["code"] == "nim-std-import")
        .expect("standard import finding must exist");
    assert_eq!(standard_import["path"], "src/main.nim");
    assert_eq!(standard_import["line"], 1);
    assert_eq!(
        standard_import["message"],
        "standard-library import should use std/ prefix"
    );
    assert_eq!(standard_import["confidence"], "medium");
}

#[test]
fn summary_reports_fastapi_rule_family_when_dependency_is_detected() {
    let root = TempDirectory::new("cbr-fastapi");
    root.write("requirements.txt", b"fastapi==0.115.0\n");
    root.write(
        "app/api.py",
        br#"from fastapi import FastAPI
app = FastAPI()
@app.get("/users")
def users():
    return {"users": []}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "fastapi-route-missing-response-model")
        .expect("FastAPI response-model finding must exist");

    assert_eq!(finding["path"], "app/api.py");
    assert_eq!(finding["line"], 3);
    assert_eq!(
        finding["message"],
        "GET /users returns an object without a response model"
    );
    assert_eq!(finding["severity"], "info");
    assert_eq!(finding["confidence"], "high");
}

#[test]
fn summary_reports_flutter_quality_rules_when_framework_is_detected() {
    let root = TempDirectory::new("cbr-flutter-quality");
    root.write(
        "pubspec.yaml",
        b"name: app\nflutter:\n  uses-material-design: true\n",
    );
    root.write(
        "lib/card.dart",
        br#"class UserCard extends StatelessWidget {
  final String name;
  UserCard({required this.name});
  Widget build(BuildContext context) => Text(name);
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "flutter-widget-missing-const-constructor")
        .expect("Flutter const-constructor finding must exist");

    assert_eq!(finding["path"], "lib/card.dart");
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["end_line"], 0);
    assert_eq!(
        finding["message"],
        "UserCard is immutable but its constructor is not const"
    );
    assert_eq!(finding["severity"], "info");
    assert_eq!(finding["confidence"], "high");
}

#[test]
fn summary_reports_rust_source_rule_family() {
    let root = TempDirectory::new("cbr-rust-rules");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write(
        "src/lib.rs",
        b"pub fn load(value: Option<u32>) -> u32 {\n    value.unwrap()\n}\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "rust-unwrap")
        .expect("Rust unwrap finding must exist");

    assert_eq!(finding["path"], "src/lib.rs");
    assert_eq!(finding["line"], 2);
    assert_eq!(finding["end_line"], 0);
    assert_eq!(
        finding["message"],
        "unwrap can panic on a recoverable value"
    );
    assert_eq!(finding["severity"], "info");
    assert_eq!(finding["confidence"], "high");
}

#[test]
fn summary_reports_constant_arguments_for_private_rust_functions() {
    let root = TempDirectory::new("cbr-rust-constant-argument");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write(
        "src/lib.rs",
        b"fn new_raw(value: i32, err: Option<&str>) -> i32 {\n    let _observed = err;\n    value\n}\n\nfn first() -> i32 { new_raw(1, None) }\nfn second() -> i32 { new_raw(2, None) }\nfn third() -> i32 { new_raw(3, None) }\n",
    );

    let output = run_summary(
        &root.path,
        &["--format", "json", "--advisory", "--all-findings"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "constant-argument-parameter")
        .expect("constant argument finding must exist");

    assert_eq!(finding["path"], "src/lib.rs");
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["end_line"], 5);
    assert_eq!(
        finding["message"],
        "`new_raw` receives the constant `None` for parameter `err` at all 3 visible call sites"
    );
    assert_eq!(finding["severity"], "info");
    assert_eq!(finding["confidence"], "high");

    root.write(
        "src/lib.rs",
        b"fn new_raw(value: i32, err: Option<&str>) -> i32 {\n    let _observed = err;\n    value\n}\n\nfn first() -> i32 { new_raw(1, None) }\nfn second() -> i32 { new_raw(2, None) }\nfn third() -> i32 { new_raw(3, None) }\nfn varied() -> i32 { new_raw(4, Some(\"error\")) }\n",
    );
    let varied = run_summary(
        &root.path,
        &["--format", "json", "--advisory", "--all-findings"],
    );
    assert_eq!(varied.status.code(), Some(0));
    assert!(varied.stderr.is_empty());
    let varied_report: serde_json::Value =
        serde_json::from_slice(&varied.stdout).expect("summary must emit JSON");
    assert!(
        varied_report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .all(|finding| finding["code"] != "constant-argument-parameter")
    );
}

#[test]
fn summary_reports_complete_html_rule_family() {
    let root = TempDirectory::new("cbr-html-rules");
    root.write("code-buster.toml", b"languages = [\"html\"]\n");
    root.write(
        "index.html",
        br#"<html>
<head><script>alert(1)</script></head>
<body onclick="run()">
<button>Save</button><div role="button">Cancel</div>
<a target="_blank">open</a>
<img src="http://example.test/image.png">
<input id="name">
<div id="same"></div>
<span id="same"></span>
<form></form>
</body></html>
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let html_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("html-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        html_codes,
        std::collections::BTreeSet::from([
            "html-blank-no-rel",
            "html-duplicate-id",
            "html-form-method",
            "html-http-resource",
            "html-img-alt",
            "html-inline-event",
            "html-inline-script",
            "html-input-label",
            "html-missing-lang",
            "html-missing-title",
            "html-missing-viewport",
            "html-parallel-control-pattern",
        ])
    );
}

#[test]
fn summary_reports_complete_css_rule_family() {
    let root = TempDirectory::new("cbr-css-rules");
    root.write("code-buster.toml", b"languages = [\"css\"]\n");
    root.write(
        "hazards.css",
        br#"* .a .b .c .d > span {
  color: red;
  color: blue !important;
  font-size: 12px;
  z-index: 9999;
  animation: pulse 1s;
  -webkit-transform: scale(1);
}
"#,
    );
    root.write(
        "primary.css",
        b".primary { color: #fff; background: #369; padding: 12px 24px; border-radius: 6px; }\n",
    );
    root.write(
        "confirm.css",
        b".confirm { border-radius: 6px; padding: 12px 24px; background: #369; color: #ffffff; }\n",
    );
    root.write(
        "tokens.css",
        b":root { --color-primary: #123456; }\n.card { color: #123456; }\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let css_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("css-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        css_codes,
        std::collections::BTreeSet::from([
            "css-animation-no-reduced-motion",
            "css-design-token-drift",
            "css-duplicate-declaration-set",
            "css-duplicate-property",
            "css-fixed-font-px",
            "css-high-z-index",
            "css-important",
            "css-selector-depth",
            "css-universal-selector",
            "css-vendor-prefix-only",
        ])
    );
}

#[test]
fn summary_reports_complete_regex_rule_family() {
    let root = TempDirectory::new("cbr-regex-rules");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write(
        "patterns.dart",
        br#"final invalid = RegExp(r'[');
final literal = RegExp('x');
final first = RegExp('[A-z]+');
final second = RegExp('[A-z]+');
if (RegExp('ordinary').hasMatch(input)) {}
final RegExpMatch? ordinaryMatch = RegExp('ordinary').firstMatch(input);
final validationEmail = RegExp('.*(a+)+|');
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let regex_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("regex-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        regex_codes,
        std::collections::BTreeSet::from([
            "regex-a-z-range",
            "regex-catastrophic-backtracking-risk",
            "regex-empty-alternative",
            "regex-invalid",
            "regex-leading-dot-star",
            "regex-repeated-compile",
            "regex-single-literal",
            "regex-unanchored-validation",
        ])
    );
}

#[test]
fn summary_reports_complete_mojo_rule_family() {
    let root = TempDirectory::new("cbr-mojo-rules");
    root.write("code-buster.toml", b"languages = [\"mojo\"]\n");
    root.write(
        "main.mojo",
        br#"from pathlib import Path

alias Size = Int

@parameter
fn legacy(inout value: Int):
    let text = "hello"
    print(text[0])

def fail():
    raise Error("failed")

# let ignored = 1
var example = "fn ignored()"
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let mojo_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("mojo-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        mojo_codes,
        std::collections::BTreeSet::from([
            "mojo-deprecated-alias",
            "mojo-deprecated-fn",
            "mojo-deprecated-let",
            "mojo-legacy-argument-convention",
            "mojo-legacy-stdlib-import",
            "mojo-missing-raises",
            "mojo-parameter-decorator",
            "mojo-string-index",
        ])
    );
}

#[test]
fn summary_reports_complete_svelte_rule_family() {
    let root = TempDirectory::new("cbr-svelte-rules");
    root.write("code-buster.toml", b"languages = [\"html\"]\n");
    root.write("package.json", br#"{"dependencies":{"svelte":"^5.0.0"}}"#);
    root.write(
        "src/Panel.svelte",
        br#"<script module>
  const width = window.innerWidth;
</script>
<script lang="ts">
  import { onMount } from 'svelte';
  import { flip } from 'svelte/animate';
  let content = $state('');
  onMount(async () => {
    window.addEventListener('resize', resize);
    setInterval(refresh, 1000);
    await refresh();
    return () => refresh();
  });
</script>
{#each rows as row}
  <div animate:flip>{row.name}</div>
{/each}
<section>{@html content}</section>
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let svelte_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("svelte-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        svelte_codes,
        std::collections::BTreeSet::from([
            "svelte-animate-unkeyed-each",
            "svelte-async-onmount-cleanup",
            "svelte-dynamic-html",
            "svelte-global-listener-without-cleanup",
            "svelte-interval-without-cleanup",
            "svelte-module-browser-global",
        ])
    );
}

#[test]
fn summary_reports_complete_mvvm_rule_family() {
    let root = TempDirectory::new("cbr-mvvm-rules");
    root.write(
        "code-buster.toml",
        b"languages = [\"dart\"]\n[architecture]\nprofile = \"dart-mvvm\"\n",
    );
    root.write(
        "pubspec.yaml",
        b"dependencies:\n  flutter:\n    sdk: flutter\n",
    );
    root.write(
        "lib/views/login_page.dart",
        b"import '../data/login_repository.dart';\nclass LoginPage {}\n",
    );
    root.write(
        "lib/data/login_repository.dart",
        b"class LoginRepository {}\n",
    );
    root.write(
        "lib/models/user_model.dart",
        b"import 'package:flutter/widgets.dart';\nclass UserModel {}\n",
    );
    root.write(
        "lib/view_models/login_view_model.dart",
        br#"class LoginViewModel {
  Widget build(BuildContext context) {
    Navigator.of(context);
    return const SizedBox();
  }
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let mvvm_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("mvvm-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        mvvm_codes,
        std::collections::BTreeSet::from([
            "mvvm-forbidden-dependency",
            "mvvm-model-imports-ui",
            "mvvm-viewmodel-performs-navigation",
            "mvvm-viewmodel-returns-widget",
            "mvvm-viewmodel-ui-context",
        ])
    );
}

#[test]
fn summary_reports_complete_pixijs_rule_family() {
    let root = TempDirectory::new("cbr-pixijs-rules");
    root.write("code-buster.toml", b"languages = [\"typescript\"]\n");
    root.write("package.json", br#"{"dependencies":{"pixi.js":"^8.0.0"}}"#);
    root.write(
        "src/game.ts",
        br#"import { Application, Graphics, Text } from 'pixi.js';
const app = new Application();
app.init({ background: '#000' });
button.interactive = true;
world.cacheAsBitmap = true;
function update() {}
app.ticker.add(update);
app.ticker.add((delta) => {
  player.x += delta;
  const graphics = new Graphics();
  const label = new Text({ text: 'score' });
  stage.addChild(graphics, label);
});
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let pixijs_codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| code.starts_with("pixijs-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        pixijs_codes,
        std::collections::BTreeSet::from([
            "pixijs-frame-loop-allocation",
            "pixijs-ticker-listener-without-removal",
            "pixijs-v8-cache-as-bitmap",
            "pixijs-v8-legacy-interactive",
            "pixijs-v8-numeric-ticker-delta",
            "pixijs-v8-unawaited-application-init",
        ])
    );
}

#[test]
fn summary_applies_project_pattern_rules_to_code_only() {
    let root = TempDirectory::new("cbr-pattern-rules");
    root.write(
        "code-buster.toml",
        br#"languages = ["dart"]

[rules]
patterns = ['no-debug|warn|debugCall\(|debug call committed|Remove it.|allowed|remove call|reliability']
"#,
    );
    root.write(
        "lib/main.dart",
        br#"void main() {
  debugCall(value);
  // debugCall(comment);
  final text = "debugCall(string)";
  debugCall(allowed);
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    assert_eq!(report["actionableFindingCount"], 1);
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| finding["code"] == "no-debug")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[0]["end_line"], 0);
    assert_eq!(findings[0]["severity"], "warn");
    assert_eq!(findings[0]["message"], "debug call committed");
    assert_eq!(findings[0]["confidence"], "medium");
    assert_eq!(
        findings[0]["why"],
        "This finding was produced by a project-defined pattern rule in category `reliability`."
    );
    assert_eq!(findings[0]["suggestion"], "Remove it. Fix: remove call");
}

#[test]
fn complexity_matches_dart_ast_source_normalization() {
    let root = TempDirectory::new("cbr-dart-complexity");
    root.write(
        "code-buster.toml",
        br#"languages = ["dart"]

[analysis]
complexity_threshold = 2
cognitive_complexity_threshold = 2
max_function_lines = 3
"#,
    );
    root.write(
        "lib/main.dart",
        br#"void nested() {
  if (first) {
    if (second) {
      run();
    }
  }
}
"#,
    );

    let output = run_complexity(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("complexity must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");

    assert!(
        findings
            .iter()
            .all(|finding| finding["code"] != "long-function")
    );
    assert!(findings.iter().any(|finding| {
        finding["code"] == "complex-function"
            && finding["message"] == "nested complexity=3 cognitive=2"
    }));
}

#[test]
fn summary_uses_canonical_group_for_aggregated_dart_rules() {
    let root = TempDirectory::new("cbr-dart-policy-group");
    root.write(
        "code-buster.toml",
        br#"languages = ["dart"]
rule_groups = ["dart-style"]
"#,
    );
    root.write(
        "lib/main.dart",
        br#"void main() {
  try {
    run();
  } catch (_) {}
  print('done');
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let codes = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect::<Vec<_>>();

    assert!(codes.contains(&"dart-print"));
    assert!(!codes.contains(&"dart-broad-catch"));
    assert_eq!(report["advisorySummary"]["groups"]["reliability"], 1);
}

#[test]
fn summary_manifest_uses_the_stable_cb_config_hash_contract() {
    let root = TempDirectory::new("cb-config-hash");
    root.write(
        "code-buster.toml",
        b"lang = \"dart\"\n\n[severity]\nz-rule = \"warn\"\na-rule = \"info\"\n",
    );
    root.write("lib/main.dart", b"void main() {}\n");

    let output = run_summary(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");

    let first = report["manifest"]["configHash"]
        .as_str()
        .expect("config hash must be a string")
        .to_owned();
    let repeated = run_summary(&root.path, &["--format", "json", "--no-cache"]);
    let repeated: serde_json::Value =
        serde_json::from_slice(&repeated.stdout).expect("repeated summary must emit JSON");
    assert_eq!(repeated["manifest"]["configHash"], first);

    root.write(
        "code-buster.toml",
        b"lang = \"dart\"\n\n[severity]\nz-rule = \"warn\"\na-rule = \"warn\"\n",
    );
    let changed = run_summary(&root.path, &["--format", "json", "--no-cache"]);
    let changed: serde_json::Value =
        serde_json::from_slice(&changed.stdout).expect("changed summary must emit JSON");
    assert_ne!(changed["manifest"]["configHash"], first);
}

#[test]
fn summary_reports_single_use_trivial_wrapper() {
    let root = TempDirectory::new("cbr-trivial-wrapper");
    root.write(
        "src/lib.rs",
        br#"fn normalize(input: &str) -> String {
    input.trim().to_owned()
}

fn normalize_name(input: &str) -> String {
    normalize(input)
}

pub fn display_name(value: &str) -> String {
    normalize_name(value)
}
"#,
    );

    let output = run_summary(&root.path, &["--format", "json", "--advisory"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| finding["code"] == "single-use-trivial-wrapper")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["path"], "src/lib.rs");
    assert_eq!(findings[0]["line"], 5);
    assert_eq!(findings[0]["end_line"], 8);
    assert_eq!(
        findings[0]["message"],
        "`normalize_name` has one caller and only forwards unchanged arguments to `normalize`"
    );
}
#[test]
fn summary_groups_concentrated_yagni_findings_by_file() {
    let root = TempDirectory::new("cbr-yagni-concentration");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write(
        "src/lib.rs",
        br#"fn normalize(input: &str) -> String {
    input.trim().to_owned()
}

fn normalize_name(input: &str) -> String {
    normalize(input)
}

pub fn display_name(value: &str) -> String {
    normalize_name(value)
}

fn encode(input: &str) -> String {
    input.to_owned()
}

fn encode_name(input: &str) -> String {
    encode(input)
}

pub fn encoded_name(value: &str) -> String {
    encode_name(value)
}

fn new_raw(value: i32, err: Option<&str>) -> i32 {
    let _observed = err;
    value
}

fn first() -> i32 { new_raw(1, None) }
fn second() -> i32 { new_raw(2, None) }
fn third() -> i32 { new_raw(3, None) }
"#,
    );

    let output = run_summary(
        &root.path,
        &["--format", "json", "--advisory", "--all-findings"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let concentration = findings
        .iter()
        .find(|finding| finding["code"] == "yagni-concentration")
        .expect("concentrated YAGNI evidence must produce holistic guidance");

    assert_eq!(concentration["path"], "src/lib.rs");
    assert_eq!(concentration["line"], 5);
    assert_eq!(
        concentration["message"],
        "3 YAGNI findings from 2 rule families are concentrated in this file: constant-argument-parameter, single-use-trivial-wrapper"
    );
    assert_eq!(concentration["confidence"], "medium");
    assert_eq!(
        concentration["suggestion"],
        "Start from the actual callers and required behavior, then remove unused variation and collapse one-use layers together; retain boundaries that own policy, validation, lifecycle, or an external contract."
    );
}

#[test]
fn summary_reports_repository_wide_yagni_rules() {
    let root = TempDirectory::new("cbr-yagni-repository-rules");
    root.write(
        "code-buster.toml",
        br#"languages = ["dart"]

[rules.mode]
single-product-factory = "report"
unused-customization-hook = "report"
unused-optional-parameter = "report"
unused-configuration-option = "report"
yagni-concentration = "report"
"#,
    );
    root.write(
        "lib/example.dart",
        br#"class Renderer {
  Renderer(int scale);
}

class RenderOptions {
  const RenderOptions({required this.cache, required this.trace});
  final bool cache;
  final bool trace;
}

Renderer _createRenderer(int scale) => Renderer(scale);

int _render(int value, RenderOptions options, {int Function(int)? customize, bool validate = true}) {
  final rendered = customize?.call(value) ?? value;
  if (validate && options.cache) return rendered;
  return 0;
}

int _configure(int value, RenderOptions options) {
  return options.cache ? value : 0;
}

Renderer makeRenderer() => _createRenderer(2);
int first() => _render(1, const RenderOptions(cache: true, trace: false));
int second() => _render(2, const RenderOptions(cache: false, trace: true));
int third() => _render(3, const RenderOptions(cache: true, trace: true));
int configFirst() => _configure(1, const RenderOptions(cache: true, trace: false));
int configSecond() => _configure(2, const RenderOptions(cache: false, trace: true));
int configThird() => _configure(3, const RenderOptions(cache: true, trace: true));
"#,
    );

    let output = run_summary(
        &root.path,
        &["--format", "json", "--no-cache", "--all-findings"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let selected = serde_json::Value::Array(
        findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding["code"].as_str(),
                    Some(
                        "single-product-factory"
                            | "unused-customization-hook"
                            | "unused-optional-parameter"
                            | "unused-configuration-option"
                            | "yagni-concentration"
                    )
                )
            })
            .map(|finding| {
                serde_json::json!({
                    "code": finding["code"],
                    "path": finding["path"],
                    "line": finding["line"],
                    "end_line": finding["end_line"],
                    "message": finding["message"],
                })
            })
            .collect::<Vec<_>>(),
    );

    assert_eq!(
        selected,
        serde_json::json!([
            {
                "code": "single-product-factory",
                "path": "lib/example.dart",
                "line": 11,
                "end_line": 11,
                "message": "`_createRenderer` has one caller and only constructs `Renderer` with unchanged arguments"
            },
            {
                "code": "unused-customization-hook",
                "path": "lib/example.dart",
                "line": 13,
                "end_line": 13,
                "message": "`_render` exposes optional customization hook `customize`, but none of its 3 visible callers supplies it"
            },
            {
                "code": "unused-optional-parameter",
                "path": "lib/example.dart",
                "line": 13,
                "end_line": 13,
                "message": "`_render` exposes optional parameter `validate`, but none of its 3 visible callers supplies it"
            },
            {
                "code": "unused-configuration-option",
                "path": "lib/example.dart",
                "line": 19,
                "end_line": 19,
                "message": "`_configure` receives configuration option `trace` from all 3 visible callers but never reads it"
            },
            {
                "code": "yagni-concentration",
                "path": "lib/example.dart",
                "line": 11,
                "end_line": 0,
                "message": "4 YAGNI findings from 4 rule families are concentrated in this file: single-product-factory, unused-configuration-option, unused-customization-hook, unused-optional-parameter"
            }
        ])
    );
}

#[test]
fn summary_reports_dart_package_cycles() {
    let root = TempDirectory::new("cbr-dart-package-cycle");
    root.write(
        "code-buster.toml",
        br#"languages = ["dart"]

[architecture]
profile = "dart-mvvm"

[rules.mode]
dart-package-cycle = "report"
"#,
    );
    root.write(
        "packages/alpha/lib/alpha.dart",
        b"import 'package:beta/beta.dart';\n\nint alpha() => beta();\n",
    );
    root.write(
        "packages/beta/lib/beta.dart",
        b"import 'package:alpha/alpha.dart';\n\nint beta() => alpha();\n",
    );

    let output = run_summary(&root.path, &["--format", "json", "--no-cache"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "dart-package-cycle")
        .expect("package dependency cycle must be reported");

    assert_eq!(finding["path"], "alpha");
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["end_line"], 0);
    assert_eq!(
        finding["message"],
        "Dart package cycle: alpha -> beta -> alpha"
    );
    assert_eq!(finding["related_files"], serde_json::json!(["beta"]));
}

#[test]
fn summary_reports_files_above_the_configured_line_limit() {
    let root = TempDirectory::new("cbr-large-file");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nmax_file_lines = 4\n[rules.mode]\nlarge-file = \"report\"\n",
    );
    root.write(
        "src/lib.rs",
        b"pub fn first() {}\npub fn second() {}\npub fn third() {}\n",
    );

    let at_limit = run_summary(&root.path, &["--format", "json", "--no-cache"]);
    assert_eq!(at_limit.status.code(), Some(0));
    let at_limit_report: serde_json::Value =
        serde_json::from_slice(&at_limit.stdout).expect("summary must emit JSON");
    assert!(
        at_limit_report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .all(|finding| finding["code"] != "large-file")
    );

    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nmax_file_lines = 2\n[rules.mode]\nlarge-file = \"report\"\n",
    );
    let over_limit = run_summary(&root.path, &["--format", "json", "--no-cache"]);
    assert_eq!(over_limit.status.code(), Some(0));
    assert!(over_limit.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&over_limit.stdout).expect("summary must emit JSON");
    let finding = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .find(|finding| finding["code"] == "large-file")
        .expect("file above the configured limit must be reported");

    assert_eq!(finding["path"], "src/lib.rs");
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["end_line"], 1);
    assert_eq!(finding["message"], "4 lines > 2");
    assert_eq!(finding["confidence"], "high");
    assert_eq!(
        finding["suggestion"],
        "Split the file along cohesive module responsibilities."
    );
}

#[test]
fn summary_reports_distributed_python_and_rust_object_soup() {
    let root = TempDirectory::new("cbr-object-soup");
    root.write(
        "code-buster.toml",
        b"languages = [\"python\", \"rust\"]\n",
    );
    root.write(
        "python/user.py",
        b"def display(user: dict[str, object]):\n    return user[\"id\"], user[\"email\"], user[\"role\"], user[\"active\"]\n\ndef authorize(user):\n    return user.get(\"id\"), user.get(\"email\"), user.get(\"role\"), user.get(\"active\")\n\ndef render_profile(name: str, email: str, role: str, active: bool):\n    return name, email, role, active\n\ndef validate_profile(active: bool, role: str, email: str, name: str):\n    return active, role, email, name\n",
    );
    root.write(
        "python/audit.py",
        b"def audit(user: dict):\n    return user[\"id\"], user[\"email\"], user[\"role\"], user[\"active\"]\n\ndef audit_profile(name: str, email: str, role: str, active: bool):\n    return name, email, role, active\n",
    );
    root.write(
        "tests/test_users.py",
        b"def test_user(user):\n    return user[\"id\"], user[\"email\"], user[\"role\"], user[\"active\"]\n",
    );
    root.write(
        "src/user.rs",
        br#"fn display(user: &HashMap<String, Value>) {
    let _ = (&user["id"], &user["email"], &user["role"], &user["active"]);
}
fn authorize(user: &HashMap<String, Value>) {
    let _ = (user.get("id"), user.get("email"), user.get("role"), user.get("active"));
}
fn render_profile(name: &str, email: &str, role: &str, active: bool) {
    let _ = (name, email, role, active);
}
fn validate_profile(active: bool, role: &str, email: &str, name: &str) {
    let _ = (active, role, email, name);
}
"#,
    );
    root.write(
        "src/audit.rs",
        br#"fn audit(user: &BTreeMap<String, serde_json::Value>) {
    let _ = (&user["id"], &user["email"], &user["role"], &user["active"]);
}
fn audit_profile(name: &str, email: &str, role: &str, active: bool) {
    let _ = (name, email, role, active);
}
"#,
    );

    let output = run_summary(
        &root.path,
        &["--format", "json", "--no-cache", "--advisory", "--all-findings"],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let finding = |code: &str| {
        findings
            .iter()
            .find(|finding| finding["code"] == code)
            .unwrap_or_else(|| panic!("{code} must be reported"))
    };

    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding["code"].as_str(),
                    Some(
                        "py-object-soup"
                            | "py-repeated-dictionary-shape"
                            | "rust-object-soup"
                            | "rust-repeated-dynamic-map-shape"
                    )
                )
            })
            .count(),
        4
    );
    for code in [
        "py-object-soup",
        "py-repeated-dictionary-shape",
        "rust-object-soup",
        "rust-repeated-dynamic-map-shape",
    ] {
        assert_eq!(finding(code)["confidence"], "medium");
        assert_eq!(
            finding(code)["related_files"].as_array().unwrap().len(),
            2
        );
    }
    assert_eq!(finding("py-object-soup")["path"], "python/audit.py");
    assert_eq!(
        finding("py-repeated-dictionary-shape")["path"],
        "python/audit.py"
    );
    assert_eq!(finding("rust-object-soup")["path"], "src/audit.rs");
    assert_eq!(
        finding("rust-repeated-dynamic-map-shape")["path"],
        "src/audit.rs"
    );
}

#[test]
fn summary_reports_production_imports_of_excluded_test_code() {
    let root = TempDirectory::new("cb-production-imports-test-code");
    root.write("package.json", br#"{"private":true,"type":"module"}"#);
    root.write(
        "src/main.ts",
        b"import { fixture } from '../tests/fixture';\n\
          import { helper } from './helper';\n\
          export const result = fixture(helper());\n",
    );
    root.write(
        "src/helper.ts",
        b"export function helper(): string { return 'safe'; }\n",
    );
    root.write(
        "src/example.ts",
        b"const sample = \"import '../tests/fixture'\";\n\
          // import { fixture } from '../tests/fixture';\n\
          export { sample };\n",
    );
    root.write(
        "tests/fixture.ts",
        b"export function fixture(value: string): string { return value; }\n",
    );

    let output = run_summary(
        &root.path,
        &[
            "--format",
            "json",
            "--no-cache",
            "--only",
            "production-imports-test-code",
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(findings.len(), 1, "unexpected findings: {findings:#?}");
    assert_eq!(findings[0]["code"], "production-imports-test-code");
    assert_eq!(findings[0]["path"], "src/main.ts");
    assert_eq!(findings[0]["related_files"][0], "tests/fixture.ts");
}
