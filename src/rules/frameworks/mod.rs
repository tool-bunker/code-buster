pub(crate) mod fastapi;
pub(crate) mod flutter;
pub(crate) mod pixijs;
pub(crate) mod svelte;

pub(crate) fn mask_javascript(source: &str, strings: bool, html_comments: bool) -> String {
    JavascriptMasker::new(source, strings, html_comments).mask()
}

#[derive(Clone, Copy)]
enum JavascriptRegion {
    HtmlComment,
    LineComment,
    BlockComment,
    Quoted(u8),
}

struct JavascriptMasker<'a> {
    source: &'a str,
    bytes: &'a [u8],
    masked: String,
    index: usize,
    literal_start: usize,
    strings: bool,
    html_comments: bool,
}

impl<'a> JavascriptMasker<'a> {
    fn new(source: &'a str, strings: bool, html_comments: bool) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            masked: String::with_capacity(source.len()),
            index: 0,
            literal_start: 0,
            strings,
            html_comments,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.bytes.len() {
            if let Some(region) = self.region_at_index() {
                self.mask_region(region);
            } else {
                self.index += 1;
            }
        }
        self.masked
            .push_str(&self.source[self.literal_start..self.index]);
        self.masked
    }

    fn region_at_index(&self) -> Option<JavascriptRegion> {
        if self.html_comments && self.starts_with(b"<!--") {
            return Some(JavascriptRegion::HtmlComment);
        }
        if self.starts_with(b"//") {
            return Some(JavascriptRegion::LineComment);
        }
        if self.starts_with(b"/*") {
            return Some(JavascriptRegion::BlockComment);
        }
        if self.strings {
            let quote = self.bytes[self.index];
            if matches!(quote, b'"' | b'\'' | b'`') {
                return Some(JavascriptRegion::Quoted(quote));
            }
        }
        None
    }

    fn mask_region(&mut self, region: JavascriptRegion) {
        self.masked
            .push_str(&self.source[self.literal_start..self.index]);
        match region {
            JavascriptRegion::HtmlComment => self.mask_html_comment(),
            JavascriptRegion::LineComment => self.mask_line_comment(),
            JavascriptRegion::BlockComment => self.mask_block_comment(),
            JavascriptRegion::Quoted(quote) => self.mask_quoted(quote),
        }
        self.literal_start = self.index;
    }

    fn mask_html_comment(&mut self) {
        self.mask_bytes(4);
        while self.index < self.bytes.len() {
            if self.starts_with(b"-->") {
                self.mask_bytes(3);
                break;
            }
            self.mask_byte();
        }
    }

    fn mask_line_comment(&mut self) {
        self.mask_bytes(2);
        while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
            self.mask_byte();
        }
    }

    fn mask_block_comment(&mut self) {
        self.mask_bytes(2);
        while self.index < self.bytes.len() {
            if self.starts_with(b"*/") {
                self.mask_bytes(2);
                break;
            }
            self.mask_byte();
        }
    }

    fn mask_quoted(&mut self, quote: u8) {
        self.mask_byte();
        while self.index < self.bytes.len() {
            if self.bytes[self.index] == b'\\' {
                self.mask_bytes(2);
                continue;
            }
            let closes = self.bytes[self.index] == quote;
            self.mask_byte();
            if closes {
                break;
            }
        }
    }

    fn starts_with(&self, marker: &[u8]) -> bool {
        self.bytes[self.index..].starts_with(marker)
    }

    fn mask_bytes(&mut self, count: usize) {
        let stop = self.index.saturating_add(count).min(self.bytes.len());
        while self.index < stop {
            self.mask_byte();
        }
    }

    fn mask_byte(&mut self) {
        if self.bytes[self.index] == b'\n' {
            self.masked.push('\n');
        } else {
            self.masked.push(' ');
        }
        self.index += 1;
    }
}
