use std::fmt::{self, Display};

use crate::config::Config;
use crate::findings::Finding;

pub(super) struct HumanMessage<'a> {
    pub subject: &'a str,
    pub concern: &'a str,
    pub grouping: &'a str,
    pub detail: Option<Detail<'a>>,
}

impl Display for HumanMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.subject.is_empty() {
            write!(formatter, "{} ", self.subject)?;
        }
        formatter.write_str(self.concern)?;
        if !self.grouping.is_empty() {
            write!(formatter, "; {}", self.grouping)?;
        }
        Ok(())
    }
}

pub(super) enum Detail<'a> {
    Complexity {
        cyclomatic: usize,
        cognitive: usize,
        cyclomatic_limit: i64,
        cognitive_limit: i64,
    },
    Length {
        lines: usize,
        limit: usize,
    },
    Duplication {
        lines: usize,
        fingerprint: &'a str,
    },
    JsonFields {
        written: &'a str,
        read: &'a str,
    },
    Yagni {
        findings: usize,
        families: usize,
        rules: &'a str,
    },
}

impl Display for Detail<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complexity {
                cyclomatic,
                cognitive,
                cyclomatic_limit,
                cognitive_limit,
            } => write!(
                formatter,
                "Cyclomatic {cyclomatic} (limit {cyclomatic_limit}) · Cognitive {cognitive} (limit {cognitive_limit})"
            ),
            Self::Length { lines, limit } => write!(formatter, "Lines {lines} (limit {limit})"),
            Self::Duplication { lines, fingerprint } => {
                write!(formatter, "Lines {lines} · Fingerprint {fingerprint}")
            }
            Self::JsonFields { written, read } => write!(
                formatter,
                "Written but not read: {written}; read but not written: {read}"
            ),
            Self::Yagni {
                findings,
                families,
                rules,
            } => write!(
                formatter,
                "{findings} findings · {families} rule families · Rules: {rules}"
            ),
        }
    }
}

pub(super) fn describe<'a>(finding: &'a Finding, config: &Config) -> HumanMessage<'a> {
    let message = finding.message.as_str();
    let parsed = match finding.code.as_str() {
        "complex-function" => complexity(message, config),
        "large-file" => large_file(message),
        "long-function" => long_function(message),
        "duplicate-block" => duplication(message),
        "dart-json-serialization-asymmetry" => json_fields(message),
        "yagni-concentration" => yagni(message),
        "py-broad-except" if message == "broad exception handler" => Some(broad_exception()),
        "nim-broad-except" if message == "broad exception handler catches too much" => {
            Some(broad_exception())
        }
        _ => None,
    };
    parsed.unwrap_or(HumanMessage {
        subject: "",
        concern: message,
        grouping: "",
        detail: None,
    })
}

fn broad_exception() -> HumanMessage<'static> {
    HumanMessage {
        subject: "",
        concern: "Broad exception handling can hide unrelated failures",
        grouping: "",
        detail: None,
    }
}

fn complexity<'a>(message: &'a str, config: &Config) -> Option<HumanMessage<'a>> {
    let (message, grouping) = message.split_once("; ").unwrap_or((message, ""));
    let (prefix, cognitive) = message.rsplit_once(" cognitive=")?;
    let (subject, cyclomatic) = prefix.rsplit_once(" complexity=")?;
    if subject.is_empty() {
        return None;
    }
    let cyclomatic = cyclomatic.parse::<usize>().ok()?;
    let cognitive = cognitive.parse::<usize>().ok()?;
    let concern = match (
        cyclomatic as i64 > config.complexity_threshold,
        cognitive as i64 > config.cognitive_threshold,
    ) {
        (true, true) => "has too many decision paths and difficult-to-follow control flow",
        (true, false) => "has too many decision paths",
        (false, true) => "has control flow that is difficult to follow",
        (false, false) => "has complex control flow",
    };
    Some(HumanMessage {
        subject,
        concern,
        grouping,
        detail: Some(Detail::Complexity {
            cyclomatic,
            cognitive,
            cyclomatic_limit: config.complexity_threshold,
            cognitive_limit: config.cognitive_threshold,
        }),
    })
}

fn large_file(message: &str) -> Option<HumanMessage<'_>> {
    let (lines, limit) = message.split_once(" lines > ")?;
    Some(HumanMessage {
        subject: "",
        concern: "This file exceeds the configured size limit",
        grouping: "",
        detail: Some(Detail::Length {
            lines: lines.parse().ok()?,
            limit: limit.parse().ok()?,
        }),
    })
}

fn long_function(message: &str) -> Option<HumanMessage<'_>> {
    let (subject, length) = message.rsplit_once(" has ")?;
    let (lines, limit) = length.split_once(" lines (threshold ")?;
    if subject.is_empty() {
        return None;
    }
    Some(HumanMessage {
        subject,
        concern: "exceeds the configured length limit",
        grouping: "",
        detail: Some(Detail::Length {
            lines: lines.parse().ok()?,
            limit: limit.strip_suffix(')')?.parse().ok()?,
        }),
    })
}

fn duplication(message: &str) -> Option<HumanMessage<'_>> {
    let (lines, fingerprint) = message
        .strip_prefix("duplicate block of ")?
        .split_once(" lines fingerprint=")?;
    if fingerprint.len() != 12 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(HumanMessage {
        subject: "",
        concern: "This code block is duplicated elsewhere",
        grouping: "",
        detail: Some(Detail::Duplication {
            lines: lines.parse().ok()?,
            fingerprint,
        }),
    })
}

fn json_fields(message: &str) -> Option<HumanMessage<'_>> {
    let (written, read) = message
        .strip_prefix("toJson/fromJson fields differ: write-only=")?
        .rsplit_once(" read-only=")?;
    if ![written, read]
        .iter()
        .all(|fields| fields.starts_with('{') && fields.ends_with('}'))
    {
        return None;
    }
    Some(HumanMessage {
        subject: "",
        concern: "JSON serialization and deserialization disagree on fields",
        grouping: "",
        detail: Some(Detail::JsonFields { written, read }),
    })
}

fn yagni(message: &str) -> Option<HumanMessage<'_>> {
    let (findings, remainder) = message.split_once(" YAGNI findings from ")?;
    let (families, rules) =
        remainder.split_once(" rule families are concentrated in this file: ")?;
    if rules.is_empty() {
        return None;
    }
    Some(HumanMessage {
        subject: "",
        concern: "Multiple signs of unnecessary flexibility occur together",
        grouping: "",
        detail: Some(Detail::Yagni {
            findings: findings.parse().ok()?,
            families: families.parse().ok()?,
            rules,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::describe;
    use crate::config::Config;
    use crate::findings::Finding;
    use std::path::PathBuf;

    fn finding(code: &str, message: &str) -> Finding {
        Finding::structure(
            code,
            "source".to_owned(),
            message.to_owned(),
            "",
            Vec::new(),
        )
    }

    #[test]
    fn unfamiliar_or_malformed_messages_fall_back_losslessly() {
        let config = Config::defaults(PathBuf::from("."));
        for (code, message) in [
            ("external-rule", "work complexity=11 cognitive=16"),
            (
                "external-rule",
                "Imported evidence: α\n  keep spacing; and details",
            ),
            ("external-rule", ""),
            (
                "complex-function",
                "work complexity=11 cognitive=16 additional evidence",
            ),
            ("complex-function", " complexity=11 cognitive=16"),
            ("large-file", "501 lines > 500; additional evidence"),
            (
                "long-function",
                "work has 51 lines (threshold 50); more evidence",
            ),
            ("long-function", " has 51 lines (threshold 50)"),
            (
                "duplicate-block",
                "duplicate block of 6 lines fingerprint=ABCDEF012345 extra",
            ),
            (
                "duplicate-block",
                "duplicate block of 6 lines fingerprint=not-hex-data",
            ),
            (
                "dart-json-serialization-asymmetry",
                "toJson/fromJson fields differ: write-only={name} read-only=id",
            ),
            (
                "yagni-concentration",
                "4 YAGNI findings from 2 rule families are concentrated in this file: ",
            ),
            (
                "py-broad-except",
                "broad exception handler; catches user errors",
            ),
            (
                "nim-broad-except",
                "broad exception handler catches too much; retry required",
            ),
            (
                "py-broad-except",
                "broad exception handler catches too much",
            ),
            ("nim-broad-except", "broad exception handler"),
        ] {
            let finding = finding(code, message);
            let human = describe(&finding, &config);
            assert_eq!(human.to_string(), message, "{code}");
            assert!(human.detail.is_none(), "{code}: {message}");
        }
    }
}
