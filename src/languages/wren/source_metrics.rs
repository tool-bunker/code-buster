#[derive(Clone, Copy)]
enum State {
    Code,
    String,
    EscapedString,
    RawString,
    LineComment,
    BlockComment(usize),
}

/// Counts nonblank physical lines containing code or string-literal source.
/// Comments inside string interpolations are excluded just like other comments.
pub(crate) fn code_lines(source: &str) -> usize {
    let mut lexer = Lexer {
        state: State::Code,
        interpolations: Vec::new(),
    };
    let mut resume_at = 0;
    let mut lines = 0;
    let mut has_code = false;

    for (index, character) in source.char_indices() {
        if index < resume_at {
            continue;
        }
        if character == '\n' {
            lines += usize::from(has_code);
            has_code = false;
            lexer.end_line();
            continue;
        }
        let (width, is_code) = lexer.consume(&source.as_bytes()[index..]);
        resume_at = index + width;
        has_code |= is_code && !character.is_whitespace();
    }

    lines + usize::from(has_code)
}

struct Lexer {
    state: State,
    interpolations: Vec<usize>,
}

impl Lexer {
    fn end_line(&mut self) {
        self.state = match self.state {
            State::LineComment => State::Code,
            State::EscapedString => State::String,
            state => state,
        };
    }

    // Returns the delimiter width and whether the current character is source code.
    fn consume(&mut self, remaining: &[u8]) -> (usize, bool) {
        match self.state {
            State::Code => self.consume_code(remaining),
            State::String => (self.consume_string(remaining), true),
            State::EscapedString => {
                self.state = State::String;
                (1, true)
            }
            State::RawString => {
                if remaining.starts_with(b"\"\"\"") {
                    self.state = State::Code;
                    (3, true)
                } else {
                    (1, true)
                }
            }
            State::LineComment => (1, false),
            State::BlockComment(depth) => (self.consume_block_comment(remaining, depth), false),
        }
    }

    fn consume_code(&mut self, remaining: &[u8]) -> (usize, bool) {
        match remaining {
            [b'/', b'/', ..] => {
                self.state = State::LineComment;
                (2, false)
            }
            [b'/', b'*', ..] => {
                self.state = State::BlockComment(1);
                (2, false)
            }
            [b'"', b'"', b'"', ..] => {
                self.state = State::RawString;
                (3, true)
            }
            [b'"', ..] => {
                self.state = State::String;
                (1, true)
            }
            [b'(', ..] => {
                if let Some(depth) = self.interpolations.last_mut() {
                    *depth += 1;
                }
                (1, true)
            }
            [b')', ..] => {
                self.close_parenthesis();
                (1, true)
            }
            _ => (1, true),
        }
    }

    fn close_parenthesis(&mut self) {
        match self.interpolations.last_mut() {
            Some(1) => {
                self.interpolations.pop();
                self.state = State::String;
            }
            Some(depth) => *depth -= 1,
            None => {}
        }
    }

    fn consume_string(&mut self, remaining: &[u8]) -> usize {
        match remaining {
            [b'\\', ..] => {
                self.state = State::EscapedString;
                1
            }
            [b'"', ..] => {
                self.state = State::Code;
                1
            }
            [b'%', b'(', ..] => {
                self.interpolations.push(1);
                self.state = State::Code;
                2
            }
            _ => 1,
        }
    }

    fn consume_block_comment(&mut self, remaining: &[u8], depth: usize) -> usize {
        match remaining {
            [b'/', b'*', ..] => {
                self.state = State::BlockComment(depth + 1);
                2
            }
            [b'*', b'/', ..] => {
                self.state = if depth == 1 {
                    State::Code
                } else {
                    State::BlockComment(depth - 1)
                };
                2
            }
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::code_lines;

    #[test]
    fn excludes_blank_and_comment_only_lines() {
        for source in [
            "",
            " \t\r\n\n\u{2003}",
            "// comment without a final newline",
            "/* outer\n /* nested */\n still outer */\n// comment\n",
        ] {
            assert_eq!(code_lines(source), 0, "source: {source:?}");
        }
    }

    #[test]
    fn unicode_content_preserves_adjacent_comment_and_string_boundaries() {
        let source = [
            "/* λ /* 内 */ */ var text = \"",
            "λ // literal source",
            "\u{2003}",
            "\" // τέλος",
            "/* 終 */",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 3);
    }

    #[test]
    fn nested_comments_end_only_after_the_outer_close() {
        let source = [
            "/* outer",
            "  /* nested /* deeper */ nested */",
            "  still outer",
            "*/ var answer = 42 // trailing comment",
            "/* comment */ /* another */",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 1);
    }

    #[test]
    fn quotes_inside_comments_do_not_hide_nested_delimiters() {
        let source = "/* \" /* nested */\n still outer */\nvar answer = 42";
        assert_eq!(code_lines(source), 1);
    }

    #[test]
    fn ordinary_multiline_strings_retain_comment_delimiters() {
        let source = [
            "var text = \"",
            "/* outer /* nested */ outer */",
            "// literal source",
            " \t",
            "\u{2003}",
            "\"",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 4);
    }

    #[test]
    fn escaped_quotes_backslashes_and_percent_do_not_change_string_context() {
        let source = [
            r#"var text = "escaped \" quote \\ slash \%("#,
            "// literal source",
            "\"",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 3);
    }

    #[test]
    fn escaped_newline_keeps_the_following_line_in_the_string() {
        let source = "var text = \"first\\\n// literal source\n\"";
        assert_eq!(code_lines(source), 3);
    }

    #[test]
    fn raw_strings_keep_nested_comments_quotes_and_interpolation_text() {
        let source = [
            "var text = \"\"\"",
            "/* outer /* nested */ outer */",
            r#"// literal " quotes "" and %( /* literal */"#,
            " \t",
            "\"\"\"",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 4);
    }

    #[test]
    fn raw_backslash_does_not_escape_the_triple_close() {
        let source = [
            r#"var text = """raw\""" // trailing comment"#,
            "/* comment-only after the raw string */",
            "var answer = 42",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 2);
    }

    #[test]
    fn interpolation_balances_parentheses_nested_strings_and_comments() {
        let source = [
            "var text = \"outer %(",
            "  call((1), \"inner %(",
            "    /* ignored ) \" %(",
            "       /* nested */",
            "    */",
            "    value // ignored ) \"",
            "  ) tail\") // ignored )",
            "  // comment-only",
            "  + next",
            ") suffix\"",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 6);
    }

    #[test]
    fn raw_strings_inside_interpolation_preserve_literal_comments() {
        let source = [
            "var text = \"%(",
            "\"\"\"raw",
            "// literal source",
            "/* nested /* literal */",
            "\"\"\" // trailing comment",
            "/* comment-only interpolation line */",
            ")\"",
        ]
        .join("\n");
        assert_eq!(code_lines(&source), 6);
    }

    #[test]
    fn single_quotes_are_not_string_delimiters() {
        let source = "' /* comment\n hidden\n*/\n'";
        assert_eq!(code_lines(source), 2);
    }

    #[test]
    fn physical_line_counts_agree_for_lf_crlf_and_missing_final_newline() {
        let lines = [
            "// heading",
            "var text = \"",
            "literal /* text */",
            " \t",
            "\"",
            "/* outer",
            " /* nested */",
            "*/ var answer = 42",
        ];
        for newline in ["\n", "\r\n"] {
            let source = lines.join(newline);
            assert_eq!(code_lines(&source), 4);
            assert_eq!(code_lines(&(source + newline)), 4);
        }
    }
}
