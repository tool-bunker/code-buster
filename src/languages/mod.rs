pub(crate) mod cpp;
pub(crate) mod csharp;
pub(crate) mod css;
pub(crate) mod dart;
pub(crate) mod functions;
pub(crate) mod go;
pub(crate) mod html;
pub(crate) mod java;
pub(crate) mod lua;
pub(crate) mod mojo;
pub(crate) mod nim;
pub(crate) mod odin;
pub(crate) mod python;
pub(crate) mod registry;
pub(crate) mod rust;
pub(crate) mod sql;
pub(crate) mod typescript;
pub(crate) mod wren;

pub(crate) use registry::*;

pub(crate) fn strip_quoted_literals(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
        } else if matches!(character, '"' | '\'' | '`') {
            quote = Some(character);
        } else {
            result.push(character);
        }
    }
    result
}
