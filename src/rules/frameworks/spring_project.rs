use std::collections::{BTreeMap, BTreeSet};

use crate::discovery::is_builtin_production_path;

/// Static, production Maven/Gradle evidence only; no build scripts are executed.
pub(crate) fn manifest_uses_spring(path: &str, source: &str) -> bool {
    let Some(path) = manifest_path(path) else {
        return false;
    };
    if path.ends_with("pom.xml") {
        MavenManifest::parse(source).is_some_and(|manifest| manifest.spring)
    } else {
        gradle_uses_spring(source)
    }
}

pub(crate) struct SpringProjects {
    modules: Vec<(String, bool)>,
}

impl SpringProjects {
    pub(crate) fn new(auxiliary: &BTreeMap<String, String>) -> Self {
        let manifests = auxiliary
            .iter()
            .filter_map(|(path, source)| manifest_path(path).map(|path| (path, source)))
            .collect::<BTreeMap<_, _>>();
        let maven = manifests
            .iter()
            .filter(|(path, _)| path.ends_with("pom.xml"))
            .filter_map(|(path, source)| {
                MavenManifest::parse(source).map(|value| (path.as_str(), value))
            })
            .collect::<BTreeMap<_, _>>();
        let mut modules = BTreeMap::new();
        for (path, source) in &manifests {
            let spring = if path.ends_with("pom.xml") {
                inherits_spring(path, &maven, &mut BTreeSet::new())
            } else {
                gradle_uses_spring(source)
            };
            let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
            *modules.entry(directory.to_owned()).or_insert(false) |= spring;
        }
        let mut modules = modules.into_iter().collect::<Vec<_>>();
        modules.sort_by(|left, right| right.0.len().cmp(&left.0.len()).then(left.0.cmp(&right.0)));
        Self { modules }
    }

    pub(crate) fn module_for(&self, path: &str) -> Option<&str> {
        let path = normalize_path(path)?;
        self.modules
            .iter()
            .find_map(|(directory, spring)| {
                let owns = directory.is_empty()
                    || path
                        .strip_prefix(directory)
                        .is_some_and(|suffix| suffix.starts_with('/'));
                owns.then_some(spring.then_some(directory.as_str()))
            })
            .flatten()
    }
}

fn manifest_path(path: &str) -> Option<String> {
    if !matches!(
        path.rsplit(['/', '\\']).next(),
        Some("pom.xml" | "build.gradle" | "build.gradle.kts")
    ) {
        return None;
    }
    let path = normalize_path(path)?;
    let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    if !directory.is_empty() && !is_builtin_production_path(directory) {
        return None;
    }
    Some(path)
}

fn normalize_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with('/') || normalized.contains(':') {
        return None;
    }
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    Some(parts.join("/"))
}

struct MavenManifest<'a> {
    group: &'a str,
    artifact: &'a str,
    version: &'a str,
    parent: Option<MavenParent<'a>>,
    spring: bool,
}

struct MavenParent<'a> {
    group: &'a str,
    artifact: &'a str,
    version: &'a str,
    relative: &'a str,
}

impl<'a> MavenManifest<'a> {
    fn parse(source: &'a str) -> Option<Self> {
        let xml = Xml::parse(source)?;
        if xml.nodes.first()?.name != "project" {
            return None;
        }
        let parent = xml.child(0, "parent").and_then(|node| {
            Some(MavenParent {
                group: xml.text(node, "groupId")?,
                artifact: xml.text(node, "artifactId")?,
                version: xml.text(node, "version")?,
                relative: xml.text(node, "relativePath").unwrap_or("../pom.xml"),
            })
        });
        let parent_spring = parent
            .as_ref()
            .is_some_and(|parent| spring_coordinate(parent.group, parent.artifact));
        let dependency_spring = xml.child(0, "dependencies").is_some_and(|dependencies| {
            xml.nodes.iter().enumerate().any(|(index, node)| {
                node.parent == Some(dependencies)
                    && node.name == "dependency"
                    && xml.text(index, "scope") != Some("test")
                    && xml
                        .text(index, "groupId")
                        .zip(xml.text(index, "artifactId"))
                        .is_some_and(|(group, artifact)| spring_coordinate(group, artifact))
            })
        });
        Some(Self {
            group: xml
                .text(0, "groupId")
                .or_else(|| parent.as_ref().map(|parent| parent.group))
                .unwrap_or(""),
            artifact: xml.text(0, "artifactId").unwrap_or(""),
            version: xml
                .text(0, "version")
                .or_else(|| parent.as_ref().map(|parent| parent.version))
                .unwrap_or(""),
            parent,
            spring: parent_spring || dependency_spring,
        })
    }
}

fn inherits_spring<'a>(
    path: &'a str,
    manifests: &BTreeMap<&'a str, MavenManifest<'_>>,
    visited: &mut BTreeSet<&'a str>,
) -> bool {
    if !visited.insert(path) {
        return false;
    }
    let Some(manifest) = manifests.get(path) else {
        return false;
    };
    if manifest.spring {
        return true;
    }
    let Some(parent) = &manifest.parent else {
        return false;
    };
    if parent.relative.is_empty() || parent.relative.contains('$') {
        return false;
    }
    let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let relative = if parent.relative.ends_with(".xml") {
        parent.relative.to_owned()
    } else {
        format!("{}/pom.xml", parent.relative.trim_end_matches('/'))
    };
    let joined = if directory.is_empty() {
        relative
    } else {
        format!("{directory}/{relative}")
    };
    let Some(parent_path) = normalize_path(&joined) else {
        return false;
    };
    let Some((key, candidate)) = manifests.get_key_value(parent_path.as_str()) else {
        return false;
    };
    if candidate.group != parent.group
        || candidate.artifact != parent.artifact
        || candidate.version != parent.version
        || parent.group.is_empty()
        || parent.artifact.is_empty()
        || parent.version.is_empty()
        || parent.group.contains('$')
        || parent.artifact.contains('$')
        || parent.version.contains('$')
    {
        return false;
    }
    inherits_spring(key, manifests, visited)
}

fn spring_coordinate(group: &str, artifact: &str) -> bool {
    (group == "org.springframework" || group.starts_with("org.springframework."))
        && artifact.starts_with("spring-")
        && !artifact.contains(['$', ' ', '<', '&'])
}

// A bounded XML tree keeps parent/child relationships, never matching comments,
// descriptions, dependencyManagement, or profile-only declarations as dependencies.
struct XmlNode<'a> {
    name: &'a str,
    parent: Option<usize>,
    start: usize,
    end: usize,
}

struct Xml<'a> {
    source: &'a str,
    nodes: Vec<XmlNode<'a>>,
}

impl<'a> Xml<'a> {
    fn parse(source: &'a str) -> Option<Self> {
        let mut nodes: Vec<XmlNode<'a>> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut offset = 0;
        while offset < source.len() {
            let rest = &source[offset..];
            if rest.starts_with("<!--") {
                offset += rest.find("-->")? + 3;
                continue;
            }
            if rest.starts_with("<?") {
                offset += rest.find("?>")? + 2;
                continue;
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').map_or(source.len(), |end| offset + end);
                if stack.is_empty() && !source[offset..end].trim().is_empty() {
                    return None;
                }
                offset = end;
                continue;
            }
            if rest.starts_with("<!") {
                return None;
            }
            let mut quote = None;
            let mut end = None;
            for (index, byte) in source.as_bytes().iter().enumerate().skip(offset + 1) {
                match (quote, *byte) {
                    (Some(delimiter), byte) if delimiter == byte => quote = None,
                    (None, b'\'' | b'"') => quote = Some(*byte),
                    (None, b'>') => {
                        end = Some(index);
                        break;
                    }
                    (None, b'<') => return None,
                    _ => {}
                }
            }
            let end = end?;
            let tag = source[offset + 1..end].trim();
            if let Some(name) = tag.strip_prefix('/') {
                let index = stack.pop()?;
                if nodes[index].name != name.trim() {
                    return None;
                }
                nodes[index].end = offset;
            } else {
                let name = tag
                    .split(|value: char| value.is_whitespace() || value == '/')
                    .next()?;
                if name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                    })
                {
                    return None;
                }
                if !xml_attributes_valid(&tag[name.len()..]) {
                    return None;
                }
                if stack.is_empty() && !nodes.is_empty() {
                    return None;
                }
                let index = nodes.len();
                nodes.push(XmlNode {
                    name,
                    parent: stack.last().copied(),
                    start: end + 1,
                    end: end + 1,
                });
                if !tag.ends_with('/') {
                    stack.push(index);
                }
            }
            offset = end + 1;
        }
        if !stack.is_empty() || nodes.is_empty() {
            return None;
        }
        Some(Self { source, nodes })
    }

    fn child(&self, parent: usize, name: &str) -> Option<usize> {
        let mut matches = self
            .nodes
            .iter()
            .enumerate()
            .skip(parent + 1)
            .take_while(|(_, node)| node.start <= self.nodes[parent].end)
            .filter(|(_, node)| node.parent == Some(parent) && node.name == name);
        let (index, _) = matches.next()?;
        matches.next().is_none().then_some(index)
    }

    fn text(&self, parent: usize, name: &str) -> Option<&'a str> {
        let node = &self.nodes[self.child(parent, name)?];
        let value = self.source[node.start..node.end].trim();
        (!value.contains(['<', '&'])).then_some(value)
    }
}

fn xml_attributes_valid(attributes: &str) -> bool {
    let mut remaining = attributes.trim();
    while !remaining.is_empty() && remaining != "/" {
        let name_end = remaining
            .find(|character: char| character.is_whitespace() || character == '=')
            .unwrap_or(remaining.len());
        let name = &remaining[..name_end];
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return false;
        }
        let Some(value) = remaining[name_end..].trim_start().strip_prefix('=') else {
            return false;
        };
        let value = value.trim_start();
        let Some(quote @ (b'\'' | b'"')) = value.as_bytes().first().copied() else {
            return false;
        };
        let Some(end) = value[1..].find(char::from(quote)) else {
            return false;
        };
        if value[1..end + 1].contains('<') {
            return false;
        }
        remaining = value[end + 2..].trim_start();
    }
    true
}

#[derive(Clone, Copy, PartialEq)]
enum GradleToken<'a> {
    Word(&'a str),
    Literal(&'a str),
    Symbol(u8),
    Newline,
}

fn gradle_tokens(source: &str) -> Option<Vec<GradleToken<'_>>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut delimiters = Vec::new();
    while index < bytes.len() {
        let start = index;
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index = source[index..]
                    .find('\n')
                    .map_or(bytes.len(), |end| index + end);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += source[index + 2..].find("*/")? + 4;
            }
            b'$' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                index += source[index..].find("/$")? + 2;
                tokens.push(GradleToken::Literal(""));
            }
            b'/' if tokens.last().is_none_or(|token| {
                matches!(token, GradleToken::Symbol(b'=' | b':' | b'(' | b',' | b'['))
            }) =>
            {
                index = escaped_literal_end(bytes, index + 1, b'/')? + 1;
                tokens.push(GradleToken::Literal(""));
            }
            b'\'' | b'"' => {
                let (token, end) = gradle_literal(source, start)?;
                tokens.push(token);
                index = end;
            }
            b'\n' => {
                tokens.push(GradleToken::Newline);
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                tokens.push(GradleToken::Word(&source[start..index]));
            }
            byte => {
                match byte {
                    b'{' | b'(' | b'[' => delimiters.push(byte),
                    b'}' | b')' | b']' => {
                        let expected = match byte {
                            b'}' => b'{',
                            b')' => b'(',
                            _ => b'[',
                        };
                        if delimiters.pop() != Some(expected) {
                            return None;
                        }
                    }
                    _ => {}
                }
                tokens.push(GradleToken::Symbol(byte));
                index += 1;
            }
        }
    }
    delimiters.is_empty().then_some(tokens)
}

fn escaped_literal_end(bytes: &[u8], mut index: usize, delimiter: u8) -> Option<usize> {
    while index < bytes.len() {
        match bytes[index] {
            byte if byte == delimiter => return Some(index),
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    None
}

fn gradle_literal(source: &str, start: usize) -> Option<(GradleToken<'_>, usize)> {
    let bytes = source.as_bytes();
    let quote = bytes[start];
    if bytes
        .get(start..start + 3)
        .is_some_and(|value| value == [quote, quote, quote])
    {
        let marker = &source[start..start + 3];
        let end = start + 3 + source[start + 3..].find(marker)? + 3;
        return Some((GradleToken::Literal(""), end));
    }
    let end = escaped_literal_end(bytes, start + 1, quote)?;
    let literal = &source[start + 1..end];
    let value = if literal.contains(['$', '\\']) {
        ""
    } else {
        literal
    };
    Some((GradleToken::Literal(value), end + 1))
}

fn gradle_uses_spring(source: &str) -> bool {
    let Some(tokens) = gradle_tokens(source) else {
        return false;
    };
    let mut blocks = Vec::new();
    let mut statement_start = true;
    let mut pending_block = None;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            GradleToken::Symbol(b'{') => {
                blocks.push(pending_block.take());
                statement_start = true;
            }
            GradleToken::Symbol(b'}') => {
                blocks.pop();
                statement_start = true;
            }
            GradleToken::Newline | GradleToken::Symbol(b';') => statement_start = true,
            GradleToken::Word(name) if statement_start => {
                let tail = &tokens[index + 1..];
                pending_block = matches!(
                    tail.iter().find(|token| **token != GradleToken::Newline),
                    Some(GradleToken::Symbol(b'{'))
                )
                .then_some(*name);
                if blocks.as_slice() == [Some("dependencies")]
                    && production_configuration(name)
                    && gradle_dependency(tail)
                {
                    return true;
                }
                if blocks.as_slice() == [Some("plugins")]
                    && *name == "id"
                    && first_literal(tail) == Some("org.springframework.boot")
                    && !tail
                        .windows(2)
                        .take_while(|pair| {
                            !matches!(
                                pair[0],
                                GradleToken::Newline | GradleToken::Symbol(b';' | b'}')
                            )
                        })
                        .any(|pair| {
                            pair == [GradleToken::Word("apply"), GradleToken::Word("false")]
                        })
                {
                    return true;
                }
                if blocks.is_empty()
                    && *name == "apply"
                    && matches!(
                        tail,
                        [
                            GradleToken::Word("plugin"),
                            GradleToken::Symbol(b':'),
                            GradleToken::Literal("org.springframework.boot"),
                            ..
                        ] | [
                            GradleToken::Symbol(b'('),
                            GradleToken::Word("plugin"),
                            GradleToken::Symbol(b'='),
                            GradleToken::Literal("org.springframework.boot"),
                            ..
                        ]
                    )
                {
                    return true;
                }
                statement_start = false;
            }
            _ => statement_start = false,
        }
    }
    false
}

fn production_configuration(name: &str) -> bool {
    matches!(
        name,
        "implementation"
            | "api"
            | "compile"
            | "compileOnly"
            | "runtime"
            | "runtimeOnly"
            | "annotationProcessor"
            | "compileOnlyApi"
    )
}

fn first_literal<'a>(tokens: &[GradleToken<'a>]) -> Option<&'a str> {
    let mut tokens = tokens;
    if tokens.first() == Some(&GradleToken::Symbol(b'(')) {
        tokens = &tokens[1..];
    }
    let token = tokens
        .iter()
        .find(|token| **token != GradleToken::Newline)?;
    match token {
        GradleToken::Literal(value) => Some(value),
        _ => None,
    }
}

fn gradle_dependency(tokens: &[GradleToken<'_>]) -> bool {
    if let Some(value) = first_literal(tokens) {
        let mut parts = value.split(':');
        return parts
            .next()
            .zip(parts.next())
            .is_some_and(|(group, artifact)| spring_coordinate(group, artifact));
    }
    let tokens = if matches!(tokens.first(), Some(GradleToken::Symbol(b'('))) {
        &tokens[1..]
    } else {
        tokens
    };
    let mut group = None;
    let mut artifact = None;
    let mut index = 0;
    while index + 2 < tokens.len() {
        match (&tokens[index], &tokens[index + 1], &tokens[index + 2]) {
            (
                GradleToken::Word(name),
                GradleToken::Symbol(b':' | b'='),
                GradleToken::Literal(value),
            ) => {
                match *name {
                    "group" => group = Some(*value),
                    "name" => artifact = Some(*value),
                    _ => {}
                }
                index += 3;
                if tokens.get(index) == Some(&GradleToken::Symbol(b',')) {
                    index += 1;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    group
        .zip(artifact)
        .is_some_and(|(group, artifact)| spring_coordinate(group, artifact))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPRING: &str = "<project><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-context</artifactId></dependency></dependencies></project>";

    #[test]
    fn recognizes_real_maven_dependencies_and_boot_parent() {
        assert!(manifest_uses_spring("pom.xml", SPRING));
        assert!(manifest_uses_spring(
            "app/pom.xml",
            "<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3</version></parent></project>"
        ));
        for source in [
            "<project><!-- <dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-context</artifactId></dependency></dependencies> --></project>",
            "<project><description>org.springframework:spring-context</description></project>",
            "<project><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-test</artifactId><scope>test</scope></dependency></dependencies></project>",
            "<project><dependencyManagement><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-context</artifactId></dependency></dependencies></dependencyManagement></project>",
            "<project><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-context</artifactId></dependency></dependencies>",
            "<project malformed><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-context</artifactId></dependency></dependencies></project>",
        ] {
            assert!(!manifest_uses_spring("pom.xml", source), "{source}");
        }
        for path in [
            "tests/pom.xml",
            "build/generated/pom.xml",
            "vendor/pom.xml",
            "fixtures/build.gradle",
        ] {
            assert!(!manifest_uses_spring(path, SPRING), "{path}");
        }
    }

    #[test]
    fn recognizes_groovy_and_kotlin_declarations_not_descriptive_literals() {
        for source in [
            "dependencies { implementation 'org.springframework:spring-context:6' }",
            "dependencies {\n implementation(\n \"org.springframework.boot:spring-boot-starter:3\"\n )\n}",
            "dependencies { implementation(group = \"org.springframework\", name = \"spring-context\", version = \"6\") }",
            "plugins { id(\"org.springframework.boot\") version \"3\" }",
            "apply plugin: 'org.springframework.boot'",
        ] {
            for path in ["build.gradle", "build.gradle.kts"] {
                assert!(manifest_uses_spring(path, source), "{source}");
            }
        }
        for source in [
            "// plugins { id 'org.springframework.boot' }",
            "/* dependencies { implementation 'org.springframework:spring-context:6' } */",
            "description = \"org.springframework:spring-context:6\"",
            "val sample = \"dependencies { implementation 'org.springframework:spring-context:6' }\"",
            "dependencies { testImplementation('org.springframework:spring-test:6') }",
            "task sample { dependencies { implementation 'org.springframework:spring-context:6' } }",
            "dependencies { implementation 'org.springframework:spring-context:6'",
            "plugins { id('other') // org.springframework.boot\n }",
            "plugins { id('org.springframework.boot') version '3' apply false }",
            "val fake = dependencies { implementation 'org.springframework:spring-context:6' }",
            "description = '''\ndependencies { implementation 'org.springframework:spring-context:6' }\n'''",
            "description = /\ndependencies { implementation 'org.springframework:spring-context:6' }\n/",
            "description = $/\ndependencies { implementation 'org.springframework:spring-context:6' }\n/$",
        ] {
            assert!(!manifest_uses_spring("build.gradle", source), "{source}");
        }
    }

    #[test]
    fn scopes_to_nearest_module_even_when_nested_manifest_is_malformed() {
        let projects = SpringProjects::new(&BTreeMap::from([
            ("pom.xml".to_owned(), SPRING.to_owned()),
            ("utility/pom.xml".to_owned(), "<project/>".to_owned()),
            (
                "broken/build.gradle.kts".to_owned(),
                "dependencies {".to_owned(),
            ),
        ]));
        assert_eq!(projects.module_for("src/main/java/Service.java"), Some(""));
        assert_eq!(projects.module_for("utility/src/Service.java"), None);
        assert_eq!(projects.module_for("broken/src/Service.java"), None);
        assert_eq!(projects.module_for("utility-extra/Service.java"), Some(""));
    }

    #[test]
    fn inherits_only_coordinate_matched_local_maven_parents() {
        let child = |relative: &str, artifact: &str| {
            format!(
                "<project><parent><groupId>example</groupId><artifactId>{artifact}</artifactId><version>1</version><relativePath>{relative}</relativePath></parent><artifactId>child</artifactId></project>"
            )
        };
        let projects = SpringProjects::new(&BTreeMap::from([
            ("parent/pom.xml".to_owned(), SPRING.to_owned()),
            (
                "child/pom.xml".to_owned(),
                child("../parent/pom.xml", "parent"),
            ),
            (
                "unrelated/pom.xml".to_owned(),
                child("../parent/pom.xml", "other"),
            ),
            ("remote/pom.xml".to_owned(), child("", "parent")),
            ("parent/plain/pom.xml".to_owned(), "<project/>".to_owned()),
        ]));
        assert_eq!(projects.module_for("child/src/Main.java"), Some("child"));
        assert_eq!(projects.module_for("unrelated/src/Main.java"), None);
        assert_eq!(projects.module_for("remote/src/Main.java"), None);
        assert_eq!(projects.module_for("parent/plain/src/Main.java"), None);
    }

    #[test]
    fn scopes_gradle_siblings_and_normalized_paths_without_leaking_to_plain_java() {
        let projects = SpringProjects::new(&BTreeMap::from([
            (
                "groovy/build.gradle".to_owned(),
                "dependencies { implementation 'org.springframework:spring-context:6' }".to_owned(),
            ),
            (
                "kotlin/build.gradle.kts".to_owned(),
                "plugins { id(\"org.springframework.boot\") }".to_owned(),
            ),
            (
                "plain/build.gradle".to_owned(),
                "plugins { id 'java' }".to_owned(),
            ),
        ]));
        assert_eq!(projects.module_for("groovy/src/Main.java"), Some("groovy"));
        assert_eq!(
            projects.module_for(".\\kotlin\\src\\Main.java"),
            Some("kotlin")
        );
        assert_eq!(projects.module_for("plain/src/Main.java"), None);
        assert_eq!(projects.module_for("src/Main.java"), None);
    }
}
