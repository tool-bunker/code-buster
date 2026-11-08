use std::path::Path;

pub(crate) mod rules;

pub(crate) fn interpreter_from_shebang(first_line: &str) -> Option<&str> {
    let shebang = first_line.strip_prefix("#!")?.trim();
    let mut arguments = shebang.split_whitespace();
    let interpreter = arguments.next()?;
    let mut command = interpreter.rsplit('/').next().unwrap_or(interpreter);
    if command != "env" {
        return Some(command);
    }

    for argument in arguments {
        if argument == "-S" || argument == "--split-string" || argument == "--" {
            continue;
        }
        if argument.starts_with('-') || argument.contains('=') {
            continue;
        }
        command = argument.rsplit('/').next().unwrap_or(argument);
        return Some(command);
    }
    None
}

pub(crate) fn is_shell_interpreter(command: &str) -> bool {
    matches!(
        command,
        "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" | "mksh" | "yash"
    )
}

pub(crate) fn is_shell_source(path: &str, source: &str) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(extension, "sh" | "bash" | "zsh" | "ksh")
        || source
            .lines()
            .next()
            .and_then(interpreter_from_shebang)
            .is_some_and(is_shell_interpreter)
}

#[cfg(test)]
mod tests {
    use super::{interpreter_from_shebang, is_shell_interpreter};

    #[test]
    fn recognizes_direct_and_env_shell_shebangs() {
        for (line, expected) in [
            ("#!/bin/sh", Some("sh")),
            ("#!/usr/bin/env bash", Some("bash")),
            ("#!/usr/bin/env -S zsh -e", Some("zsh")),
            ("#!/usr/bin/env MODE=release ksh", Some("ksh")),
            ("#!/usr/bin/python3", Some("python3")),
            ("not a shebang", None),
        ] {
            assert_eq!(interpreter_from_shebang(line), expected);
        }
        assert!(is_shell_interpreter("dash"));
        assert!(is_shell_interpreter("mksh"));
        assert!(!is_shell_interpreter("python3"));
    }
}
