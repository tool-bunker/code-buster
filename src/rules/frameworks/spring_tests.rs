use std::collections::{BTreeMap, BTreeSet};

use super::analyze;
use crate::findings::Finding;
use crate::source_analysis_context::SourceAnalysisContext;

const POM: &str = r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies><dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId><version>3.4.0</version>
  </dependency></dependencies>
</project>"#;

fn findings(sources: &[(&str, &str)], manifests: &[(&str, &str)]) -> Vec<Finding> {
    let sources = sources
        .iter()
        .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let auxiliary = manifests
        .iter()
        .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let base = BTreeMap::new();
    let changed = BTreeSet::new();
    analyze(&SourceAnalysisContext::with_auxiliary(
        &sources, &base, &changed, false, &auxiliary,
    ))
}

fn line_containing(source: &str, text: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(text))
        .expect("test source must contain the requested construct")
        + 1
}

#[test]
fn reports_spring_runtime_contracts_and_groups_repeated_self_calls() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import jakarta.annotation.PostConstruct;
@Service
class Jobs {
    @Async public String invalidAsync() { return "value"; }
    @Scheduled(fixedRate = 1000) public void invalidScheduled(String input) {}
    @Async @PostConstruct public void initialize() {}
    @Transactional public void save() {}
    @Async public void work() {}
    public void run() {
        this.save();
        save();
        this.save();
        this.work();
        work();
    }
}
"#;
    let path = "src/main/java/example/Jobs.java";
    let actual = findings(&[(path, source)], &[("pom.xml", POM)]);
    let expected = [
        ("spring-async-return-type", "@Async public String", "high"),
        ("spring-scheduled-parameters", "@Scheduled", "high"),
        (
            "spring-async-post-construct",
            "@Async @PostConstruct",
            "high",
        ),
        (
            "spring-transactional-self-invocation",
            "@Transactional",
            "medium",
        ),
        (
            "spring-async-self-invocation",
            "@Async public void work",
            "medium",
        ),
    ];
    assert_eq!(actual.len(), expected.len(), "{actual:#?}");
    for (code, construct, confidence) in expected {
        let finding = actual.iter().find(|finding| finding.code == code).unwrap();
        assert_eq!(finding.path, path);
        assert_eq!(finding.line, line_containing(source, construct));
        assert_eq!(finding.confidence, confidence);
    }
    for (code, call) in [
        ("spring-transactional-self-invocation", "save();"),
        ("spring-async-self-invocation", "work();"),
    ] {
        let finding = actual.iter().find(|finding| finding.code == code).unwrap();
        let evidence_lines = finding
            .code_flow
            .iter()
            .map(|step| step.line)
            .chain(
                finding
                    .related_files
                    .iter()
                    .filter_map(|location| location.rsplit_once(':')?.1.parse::<usize>().ok()),
            )
            .collect::<BTreeSet<_>>();
        for (index, line) in source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(call))
        {
            assert!(
                evidence_lines.contains(&(index + 1)),
                "missing call evidence for {code}: {line}; {finding:#?}"
            );
        }
    }
}

#[test]
fn accepts_supported_future_returns_and_reactive_scheduled_methods() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import java.util.concurrent.Future;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.FutureTask;
import reactor.core.publisher.Mono;
@Service
class Jobs {
    @Async public void fireAndForget() {}
    @Async public Future<String> future() { return CompletableFuture.completedFuture("ok"); }
    @Async public CompletableFuture<String> promise() { return CompletableFuture.completedFuture("ok"); }
    @Async public FutureTask<String> task() { return new FutureTask<>(() -> "ok"); }
    @Async public ExternalFuture unknownSubtype() { return null; }
    @Scheduled(fixedDelay = 1000) public void tick() {}
    @Scheduled(fixedDelay = 1000) public Mono<Void> refresh() { return Mono.empty(); }
}
"#;
    assert!(
        findings(
            &[("src/main/java/example/Jobs.java", source)],
            &[("pom.xml", POM)]
        )
        .is_empty()
    );
}

#[test]
fn ignores_custom_annotations_and_unmanaged_classes() {
    let sources = [
        (
            "src/main/java/example/Custom.java",
            r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.*;
@interface Async {}
@Service class Custom {
    @Async public int ordinaryMethod() { return 1; }
}
"#,
        ),
        (
            "src/main/java/example/Other.java",
            r#"package example;
import org.springframework.stereotype.Service;
import app.Scheduled;
@Service class Other {
    @Scheduled public void ordinaryMethod(String argument) {}
}
"#,
        ),
        (
            "src/main/java/example/Plain.java",
            r#"package example;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import jakarta.annotation.PostConstruct;
class Plain {
    @Async public int ordinaryMethod() { return 1; }
    @Scheduled public void ordinarySchedule(String argument) {}
    @Async @PostConstruct public void initialize() {}
    @Transactional public void save() {}
    public void run() { this.save(); }
}
"#,
        ),
    ];
    assert!(findings(&sources, &[("pom.xml", POM)]).is_empty());
}

#[test]
fn ignores_spring_lookalikes_in_comments_strings_and_java_text_blocks() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
@Service class Examples {
    String example = """
        @Async public int bad() { return 1; }
        @Scheduled public void bad(String argument) {}
        @Async @jakarta.annotation.PostConstruct public void initialize() {}
        """;
    // @Async public int ignored() { return 1; }
    /* @Scheduled public void ignored(String argument) {} */
    public String text() { return "@Async public int ignored() {}"; }
}
"#;
    assert!(
        findings(
            &[("src/main/java/example/Examples.java", source)],
            &[("pom.xml", POM)]
        )
        .is_empty()
    );
}

#[test]
fn preserves_multiline_fully_qualified_and_crlf_annotation_locations() {
    let source = "package example;\n\
@org.springframework.stereotype.Service\n\
class Jobs {\n\
    String label = \"λ🙂\";\n\
    @org.springframework.scheduling.annotation.Async(\n\
        value = \"workers\"\n\
    )\n\
    public\n\
    int\n\
    invalidAsync() { return 1; }\n\
    @org.springframework.scheduling.annotation.Scheduled(\n\
        fixedRate = 1000\n\
    )\n\
    public void invalidSchedule(\n\
        @org.springframework.lang.Nullable String argument\n\
    ) {}\n\
}\n";
    for source in [source.to_owned(), source.replace('\n', "\r\n")] {
        let actual = findings(
            &[("src/main/java/example/Jobs.java", &source)],
            &[("pom.xml", POM)],
        );
        assert_eq!(actual.len(), 2, "{actual:#?}");
        for (code, marker) in [
            (
                "spring-async-return-type",
                "@org.springframework.scheduling.annotation.Async",
            ),
            (
                "spring-scheduled-parameters",
                "@org.springframework.scheduling.annotation.Scheduled",
            ),
        ] {
            let finding = actual.iter().find(|finding| finding.code == code).unwrap();
            assert_eq!(finding.line, line_containing(&source, marker));
        }
    }
}

const SELF_CALLS: &str = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
@Service class Jobs {
    @Async public void work() {}
    @Transactional public void save() {}
    public void run() { this.work(); this.save(); }
}
"#;

const ASPECTJ_CONFIG: &str = r#"package example;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;
@Configuration
@EnableAsync(mode = AdviceMode.ASPECTJ)
@EnableTransactionManagement(mode = AdviceMode.ASPECTJ)
class Config {}
"#;

#[test]
fn respects_explicit_aspectj_mode_without_leaking_between_modules() {
    let actual = findings(
        &[
            ("woven/src/main/java/example/Jobs.java", SELF_CALLS),
            ("woven/src/main/java/example/Config.java", ASPECTJ_CONFIG),
            ("proxied/src/main/java/example/Jobs.java", SELF_CALLS),
        ],
        &[("woven/pom.xml", POM), ("proxied/pom.xml", POM)],
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(
        actual
            .iter()
            .all(|finding| finding.path.starts_with("proxied/"))
    );
    assert_eq!(
        actual
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "spring-async-self-invocation",
            "spring-transactional-self-invocation"
        ])
    );
}

#[test]
fn aspectj_async_mode_does_not_disable_transaction_proxy_checks() {
    let config = r#"package example;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
@Configuration
@EnableAsync(mode = org.springframework.context.annotation.AdviceMode.ASPECTJ)
class Config {}
"#;
    let actual = findings(
        &[
            ("src/main/java/example/Jobs.java", SELF_CALLS),
            ("src/main/java/example/Config.java", config),
        ],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(actual[0].code, "spring-transactional-self-invocation");
}

#[test]
fn ignores_aspectj_words_without_a_real_spring_configuration_annotation() {
    let config = r#"package example;
class Notes {
    String example = "@EnableAsync(mode = AdviceMode.ASPECTJ)";
    // @EnableTransactionManagement(mode = AdviceMode.ASPECTJ)
}
"#;
    let actual = findings(
        &[
            ("src/main/java/example/Jobs.java", SELF_CALLS),
            ("src/main/java/example/Notes.java", config),
        ],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn keeps_other_receivers_nested_classes_and_deferred_callbacks_separate() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
@Service class Jobs {
    @Async public void work() {}
    @Transactional public void save() {}
    public void run(OtherBean other) { other.work(); other.save(); }
    public Runnable deferred() { return () -> { work(); save(); }; }
    class Nested { public void run() { work(); save(); } }
}
class OtherBean { public void work() {} public void save() {} }
"#;
    assert!(
        findings(
            &[("src/main/java/example/Jobs.java", source)],
            &[("pom.xml", POM)]
        )
        .is_empty()
    );
}

#[test]
fn abstains_from_ambiguous_overloaded_self_calls() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
import external.Provider;
@Service class Jobs {
    Provider provider;
    @Async public void work(Number value) {}
    public void work(Integer value) {}
    @Transactional public void save(Number value) {}
    public void save(Integer value) {}
    public void run() { work(provider.next()); this.save(provider.next()); }
}
"#;
    assert!(
        findings(
            &[("src/main/java/example/Jobs.java", source)],
            &[("pom.xml", POM)]
        )
        .is_empty()
    );
}

#[test]
fn recognizes_unambiguous_bean_factory_registration() {
    let source = r#"package example;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Async;
@Configuration class Config {
    @Bean public Jobs jobs() { return new Jobs(); }
}
class Jobs {
    @Async public int work() { return 1; }
}
"#;
    let actual = findings(
        &[("src/main/java/example/Config.java", source)],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(actual[0].code, "spring-async-return-type");
}

#[test]
fn does_not_apply_spring_rules_without_spring_project_metadata() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
@Service class Jobs { @Async public int work() { return 1; } }
"#;
    assert!(findings(&[("src/main/java/example/Jobs.java", source)], &[]).is_empty());
}

#[test]
fn class_level_async_does_not_turn_private_helpers_into_async_methods() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Async;
@Service
@Async
class Jobs {
    private int calculate() { return 1; }
    public void work() { calculate(); }
    public int invalidAsync() { return 1; }
}
"#;
    let actual = findings(
        &[("src/main/java/example/Jobs.java", source)],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(actual[0].code, "spring-async-return-type");
    assert_eq!(actual[0].line, line_containing(source, "@Async"));
}

#[test]
fn distinguishes_equivalent_transaction_settings_from_a_new_transaction_boundary() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
@Service
@Transactional
class Jobs {
    public void joined() {}
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void isolated() {}
    public void run() { this.joined(); this.isolated(); }
}
"#;
    let actual = findings(
        &[("src/main/java/example/Jobs.java", source)],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(actual[0].code, "spring-transactional-self-invocation");
    assert_eq!(actual[0].line, line_containing(source, "REQUIRES_NEW"));
}

#[test]
fn requires_new_self_invocation_still_bypasses_a_new_boundary_with_matching_settings() {
    let source = r#"package example;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
@Service
@Transactional(propagation = Propagation.REQUIRES_NEW)
class Jobs {
    public void isolated() {}
    public void run() { this.isolated(); }
}
"#;
    let actual = findings(
        &[("src/main/java/example/Jobs.java", source)],
        &[("pom.xml", POM)],
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(actual[0].code, "spring-transactional-self-invocation");
    assert_eq!(actual[0].line, line_containing(source, "REQUIRES_NEW"));
}

#[test]
fn recognizes_boot_auto_configuration_bean_factories_across_packages() {
    let config = r#"package app.autoconfigure;
import app.stats.Publisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
@AutoConfiguration
class StatsConfig {
    @Bean Publisher publisher() { return new Publisher(); }
}
"#;
    let publisher = r#"package app.stats;
import org.springframework.scheduling.annotation.Async;
public class Publisher {
    @Async public int publish() { return 1; }
}
"#;
    let actual = findings(
        &[
            ("src/main/java/app/autoconfigure/StatsConfig.java", config),
            ("src/main/java/app/stats/Publisher.java", publisher),
        ],
        &[("pom.xml", POM)],
    );
    assert_eq!(
        actual
            .iter()
            .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
            .collect::<Vec<_>>(),
        [(
            "spring-async-return-type",
            "src/main/java/app/stats/Publisher.java",
            4
        )]
    );
}

#[test]
fn distinguishes_matching_caller_context_from_new_transaction_boundaries() {
    for propagation in [
        "REQUIRED",
        "SUPPORTS",
        "MANDATORY",
        "NEVER",
        "NOT_SUPPORTED",
        "REQUIRES_NEW",
        "NESTED",
    ] {
        let source = format!(
            r#"package app;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
@Repository
class Partitions {{
    @Transactional(propagation = Propagation.{propagation})
    public void save() {{}}
    @Transactional(propagation = Propagation.{propagation})
    public void create() {{ save(); }}
}}
"#
        );
        let actual = findings(
            &[("src/main/java/app/Partitions.java", &source)],
            &[("pom.xml", POM)],
        );
        let expected = if matches!(propagation, "REQUIRES_NEW" | "NESTED") {
            vec![("spring-transactional-self-invocation", 7)]
        } else {
            Vec::new()
        };
        assert_eq!(
            actual
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            expected,
            "{propagation}"
        );
    }
}
