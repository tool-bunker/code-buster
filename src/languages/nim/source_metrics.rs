/// Count nonblank physical Nim source lines, excluding line and block comments.
/// String-literal source remains code, including multiline string contents.
pub(crate) fn code_lines(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut lines = 0;
    let mut line_has_code = false;
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let is_code = bytes[start] != b'#';
        index = token_end(bytes, start);
        for character in source[start..index].chars() {
            if matches!(character, '\r' | '\n') {
                lines += usize::from(line_has_code);
                line_has_code = false;
            } else if is_code && !character.is_whitespace() {
                line_has_code = true;
            }
        }
    }
    lines + usize::from(line_has_code)
}

fn token_end(bytes: &[u8], start: usize) -> usize {
    match bytes[start] {
        b'#' => comment_end(bytes, start),
        b'"' => string_end(bytes, start),
        b'\'' => quoted_end(bytes, start, false),
        b'`' => backtick_end(bytes, start),
        b'0'..=b'9' => number_end(bytes, start),
        _ => {
            let mut end = start + 1;
            // Keep spans on UTF-8 boundaries so Unicode whitespace is also blank.
            while end < bytes.len() && bytes[end] & 0xc0 == 0x80 {
                end += 1;
            }
            end
        }
    }
}

fn comment_end(bytes: &[u8], start: usize) -> usize {
    if bytes[start..].starts_with(b"##[") {
        return block_comment_end(bytes, start, true);
    }
    if bytes[start..].starts_with(b"#[") {
        return block_comment_end(bytes, start, false);
    }
    let mut index = start;
    while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
        index += 1;
    }
    index
}

fn backtick_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() && !matches!(bytes[index], b'`' | b'\r' | b'\n') {
        index += 1;
    }
    if bytes.get(index) == Some(&b'`') {
        index += 1;
    }
    index
}

fn number_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && (symbol_byte(bytes[index]) || bytes[index] == b'_') {
        index += 1;
    }
    // Numeric type/custom suffixes use an apostrophe, not a character literal.
    if bytes.get(index) == Some(&b'\'') {
        index += 1;
        while index < bytes.len() && (symbol_byte(bytes[index]) || bytes[index] == b'_') {
            index += 1;
        }
    }
    index
}

fn symbol_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte >= 0x80
}

fn block_comment_end(bytes: &[u8], start: usize, doc: bool) -> usize {
    let (opening, closing): (&[u8], &[u8]) = if doc {
        (b"##[", b"]##")
    } else {
        (b"#[", b"]#")
    };
    let mut depth = 1;
    let mut index = start + opening.len();
    while index < bytes.len() {
        // Like Nim's lexer, a doc block only nests doc blocks. In an ordinary
        // block, ##[ contains a nested #[ beginning at its second hash.
        if bytes[index..].starts_with(opening) {
            depth += 1;
        } else if bytes[index..].starts_with(closing) {
            depth -= 1;
            if depth == 0 {
                return index + closing.len();
            }
        }
        index += 1;
    }
    bytes.len()
}

fn string_end(bytes: &[u8], start: usize) -> usize {
    if bytes[start..].starts_with(b"\"\"\"") {
        return triple_string_end(bytes, start);
    }
    // Nim also treats identifier"text" as a raw string literal.
    let raw = start > 0 && symbol_byte(bytes[start - 1]);
    quoted_end(bytes, start, raw)
}

fn triple_string_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 3;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let run_start = index;
            while bytes.get(index) == Some(&b'"') {
                index += 1;
            }
            // A triple string closes at the last three quotes in a run.
            if index - run_start >= 3 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    index
}

fn quoted_end(bytes: &[u8], start: usize, raw: bool) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' | b'\n' => return index,
            b'\\' if !raw => index = (index + 2).min(bytes.len()),
            byte if byte == quote => {
                if raw && bytes.get(index + 1) == Some(&quote) {
                    index += 2;
                } else {
                    return index + 1;
                }
            }
            _ => index += 1,
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::code_lines;

    #[test]
    fn nested_comment_only_blocks_add_no_code_lines() {
        let source = "#[ outer\n#[ nested ]#\nouter again\n]#\n\
                      ##[ documentation\n##[ nested documentation ]##\n]##\n";
        assert_eq!(code_lines(source), 0);
    }

    #[test]
    fn follows_nim_doc_and_ordinary_nesting_rules() {
        let source = "##[ documentation\n#[ ordinary opener is just text\n]##\n\
                      let first = 1\n\
                      #[ ordinary\n##[ nested ordinary opener\n]##\n]#\n\
                      let second = 2\n";
        assert_eq!(code_lines(source), 2);
    }

    #[test]
    fn counts_quoted_comment_text_and_assigned_literals() {
        let source = r####"let ordinary = "#[ not a block ]#"
let escaped = "\" #[ still a string ]# \\"
let raw = r"\"" #[ still raw ]#"
let generalized = re"\"" ##[ still raw ]##"
let upper_raw = R"#[ raw ]#"
let character = '#'
let apostrophe = '\''
let `#[identifier]#` = 1
"####;
        assert_eq!(code_lines(source), 8);
    }

    #[test]
    fn counts_triple_strings_including_quote_runs_and_backslashes() {
        let source = r####"let text = """literal
#[ not a comment ]#
\""""
let raw = r"""##[ also literal ]##"""
let generalized = fmt"""#[ still literal ]#"""
"####;
        assert_eq!(code_lines(source), 5);
    }

    #[test]
    fn raw_trailing_backslashes_do_not_turn_following_comments_into_literals() {
        for prefix in ["r", "R", "re"] {
            let source = format!("let path = {prefix}\"\\\"\n#[ comment\n body\n]#\necho path\n");
            assert_eq!(code_lines(&source), 2, "{prefix} string");
        }
    }

    #[test]
    fn numeric_suffixes_do_not_hide_following_comments_or_code() {
        let source = "let a = 42'i32 #[ hidden\ncomment ]#\n\
                      let b = 0xFF'u8 ##[ hidden\ndoc ]##\n\
                      let c = 1.5e+2'f64 #[ hidden ]#\n\
                      let d = 123'custom #[ hidden ]#\n\
                      let e = 0b10'u #[ hidden ]#\n";
        assert_eq!(code_lines(source), 5);
    }

    #[test]
    fn line_comments_do_not_open_blocks() {
        let source = "# #[ fake opener\nlet first = 1\n\
                      ## ##[ fake documentation opener\nlet second = 2\n";
        assert_eq!(code_lines(source), 2);
    }

    #[test]
    fn counts_crlf_unicode_and_code_after_the_closing_delimiter() {
        let source = "let café = 1 #[雪\r\n#[深]#\r\n]# echo café\r\n";
        assert_eq!(code_lines(source), 2);
        assert_eq!(code_lines("#[雪\r\n]# echo \"深\""), 1);
    }

    #[test]
    fn excludes_whitespace_only_lines_inside_and_outside_strings() {
        assert_eq!(code_lines("\r\n \t\r\n\u{2003}\n"), 0);
        let source = "let text = \"\"\"\n \t\n\u{2003}\n# literal\n\"\"\"\n";
        assert_eq!(code_lines(source), 3);
        assert_eq!(code_lines("let value = 1 # trailing comment"), 1);
    }

    #[test]
    fn unterminated_blocks_hide_the_remaining_comment_lines() {
        let source = "let value = 1\n#[ unfinished\n雪\n";
        assert_eq!(code_lines(source), 1);
    }
}
