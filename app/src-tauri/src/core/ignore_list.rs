use crate::core::io::bulk_hash_error::BulkHashError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::str::FromStr;

const MAX_IGNORE_FILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
enum CharClassItem {
    Single(char),
    Range(char, char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobToken {
    Literal(char),
    AnyChar,
    AnySeq,
    CharClass {
        negated: bool,
        items: Vec<CharClassItem>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    DoubleStar,
    Glob(Vec<GlobToken>),
}

#[derive(Clone, Copy)]
struct PathSegments<'a> {
    prefix: &'a [String],
    tail: &'a str,
}

impl<'a> PathSegments<'a> {
    const fn len(self) -> usize {
        self.prefix.len() + 1
    }

    fn get(self, index: usize) -> Option<&'a str> {
        if let Some(seg) = self.prefix.get(index) {
            Some(seg.as_str())
        } else if index == self.prefix.len() {
            Some(self.tail)
        } else {
            None
        }
    }

    const fn last(self) -> &'a str {
        self.tail
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompiledRule {
    negated: bool,
    dir_only: bool,
    anchored: bool,
    segments: Vec<Segment>,
}

impl CompiledRule {
    fn matches(&self, segments: PathSegments<'_>, is_dir: bool, case_insensitive: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }

        if self.anchored {
            match_segments(&self.segments, segments, case_insensitive)
        } else {
            match self.segments.first() {
                Some(Segment::DoubleStar) => true,
                Some(Segment::Glob(tokens)) => {
                    match_segment(tokens, segments.last(), case_insensitive)
                }
                None => false,
            }
        }
    }
}

/// Configurable gitignore-style ignore list for skipping files and directories during scans.
///
/// By default (`IgnoreList::new()` / `IgnoreList::default()`), the ignore list is completely
/// empty so no user files or folders are skipped unless patterns are explicitly added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoreList {
    patterns: Vec<String>,
    rules: Vec<CompiledRule>,
    case_insensitive: bool,
}

#[derive(Serialize, Deserialize)]
struct IgnoreListRepr {
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    case_insensitive: bool,
}

impl Serialize for IgnoreList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let repr = IgnoreListRepr {
            patterns: self.patterns.clone(),
            case_insensitive: self.case_insensitive,
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IgnoreList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = IgnoreListRepr::deserialize(deserializer)?;
        let mut list = Self::new().with_case_insensitive(repr.case_insensitive);
        list.add_patterns(repr.patterns)
            .map_err(serde::de::Error::custom)?;
        Ok(list)
    }
}

impl IgnoreList {
    /// Creates a new, empty ignore list that skips no files or directories.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
            rules: Vec::new(),
            case_insensitive: false,
        }
    }

    /// Creates an ignore list from an iterator of gitignore-style pattern strings.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if any pattern has invalid syntax.
    pub fn from_patterns<I, S>(patterns: I) -> Result<Self, BulkHashError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Self::new();
        list.add_patterns(patterns)?;
        Ok(list)
    }

    /// Parses newline-delimited gitignore-style patterns from text.
    ///
    /// Blank lines and `#` comments are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if any pattern has invalid syntax.
    pub fn parse(content: &str) -> Result<Self, BulkHashError> {
        let mut list = Self::new();
        list.add_from_str(content)?;
        Ok(list)
    }

    /// Loads gitignore-style patterns from a file on disk (e.g. `.gitignore` or `.bulkhashignore`).
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, is not a regular file, cannot be read,
    /// exceeds the maximum supported size, is not valid UTF-8, or contains an invalid pattern.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BulkHashError> {
        let mut list = Self::new();
        list.add_from_file(path)?;
        Ok(list)
    }

    /// Builder method to add a single pattern.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if the pattern has invalid syntax.
    pub fn with_pattern(mut self, pattern: impl AsRef<str>) -> Result<Self, BulkHashError> {
        self.add_pattern(pattern)?;
        Ok(self)
    }

    /// Builder method to add multiple patterns.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if any pattern has invalid syntax.
    pub fn with_patterns<I, S>(mut self, patterns: I) -> Result<Self, BulkHashError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.add_patterns(patterns)?;
        Ok(self)
    }

    /// Builder method to configure case-insensitive matching.
    #[must_use]
    pub const fn with_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive = case_insensitive;
        self
    }

    /// Sets whether pattern matching is case-insensitive.
    pub const fn set_case_insensitive(&mut self, case_insensitive: bool) {
        self.case_insensitive = case_insensitive;
    }

    /// Returns whether pattern matching is case-insensitive.
    #[must_use]
    pub const fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Adds a single gitignore-style pattern to the list.
    ///
    /// Blank lines and `#` comments are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if the pattern has invalid syntax.
    pub fn add_pattern(&mut self, pattern: impl AsRef<str>) -> Result<(), BulkHashError> {
        if let Some((normalized, compiled)) = compile_rule(pattern.as_ref())? {
            self.patterns.push(normalized);
            self.rules.push(compiled);
        }
        Ok(())
    }

    /// Adds multiple gitignore-style patterns to the list atomically.
    ///
    /// If any pattern is invalid, the existing list remains unmodified.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if any pattern has invalid syntax.
    pub fn add_patterns<I, S>(&mut self, patterns: I) -> Result<(), BulkHashError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut staged_patterns = Vec::new();
        let mut staged_rules = Vec::new();

        for pattern in patterns {
            if let Some((normalized, compiled)) = compile_rule(pattern.as_ref())? {
                staged_patterns.push(normalized);
                staged_rules.push(compiled);
            }
        }

        self.patterns.extend(staged_patterns);
        self.rules.extend(staged_rules);
        Ok(())
    }

    /// Parses and appends newline-delimited patterns from a string atomically.
    ///
    /// If any pattern is invalid, the existing list remains unmodified.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidIgnorePattern`] if any line has invalid syntax.
    pub fn add_from_str(&mut self, content: &str) -> Result<(), BulkHashError> {
        let stripped = content.strip_prefix('\u{feff}').unwrap_or(content);
        self.add_patterns(stripped.lines())
    }

    /// Reads and appends gitignore-style patterns from a file on disk atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid patterns.
    pub fn add_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), BulkHashError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();

        let exists = path_ref
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !exists {
            return Err(BulkHashError::FileNotFound(path_display));
        }

        if !path_ref.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        let file = File::open(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;
        let mut buf = Vec::new();
        file.take(MAX_IGNORE_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if (buf.len() as u64) > MAX_IGNORE_FILE_BYTES {
            return Err(BulkHashError::from_io(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ignore file exceeds maximum allowed size (4 MiB)",
                ),
                path_display,
            ));
        }

        let content = String::from_utf8(buf).map_err(|_| {
            BulkHashError::from_io(
                io::Error::new(io::ErrorKind::InvalidData, "ignore file is not valid UTF-8"),
                path_display,
            )
        })?;

        self.add_from_str(&content)
    }

    /// Appends all rules from another ignore list to this one.
    pub fn extend_from(&mut self, other: &Self) {
        self.patterns.extend(other.patterns.iter().cloned());
        self.rules.extend(other.rules.iter().cloned());
    }

    /// Removes all configured patterns from the ignore list.
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.rules.clear();
    }

    /// Returns the active normalized pattern strings in evaluation order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Returns the number of active ignore rules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if no ignore patterns are configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Checks whether a path relative to the scan root should be ignored.
    ///
    /// Ancestor directories are checked top-down first so that if any parent directory is
    /// excluded (e.g. `node_modules/`), all paths underneath it are also ignored.
    #[must_use]
    pub fn is_ignored(&self, relative_path: impl AsRef<Path>, is_dir: bool) -> bool {
        if self.rules.is_empty() {
            return false;
        }

        let owned_segments = path_to_segments(relative_path.as_ref());
        let Some((last, ancestors)) = owned_segments.split_last() else {
            return false;
        };

        for idx in 0..ancestors.len() {
            if let Some(prefix) = ancestors.get(..idx)
                && let Some(tail) = ancestors.get(idx)
                && self.matches_path_segments(
                    PathSegments {
                        prefix,
                        tail: tail.as_str(),
                    },
                    true,
                )
            {
                return true;
            }
        }

        self.matches_path_segments(
            PathSegments {
                prefix: ancestors,
                tail: last.as_str(),
            },
            is_dir,
        )
    }

    /// Checks whether `full_path` located under `root` should be ignored.
    #[must_use]
    pub fn is_ignored_under(
        &self,
        root: impl AsRef<Path>,
        full_path: impl AsRef<Path>,
        is_dir: bool,
    ) -> bool {
        let full = full_path.as_ref();
        let relative = full.strip_prefix(root.as_ref()).unwrap_or(full);
        self.is_ignored(relative, is_dir)
    }

    /// Evaluates a single child entry under an already-unignored parent directory path.
    ///
    /// Used during directory traversal where ignored parent directories have already been pruned.
    pub(crate) fn matches_child(
        &self,
        parent_segments: &[String],
        entry_name: &str,
        is_dir: bool,
    ) -> bool {
        if self.rules.is_empty() || entry_name.is_empty() {
            return false;
        }

        self.matches_path_segments(
            PathSegments {
                prefix: parent_segments,
                tail: entry_name,
            },
            is_dir,
        )
    }

    fn matches_path_segments(&self, segments: PathSegments<'_>, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.negated != ignored {
                continue;
            }
            if rule.matches(segments, is_dir, self.case_insensitive) {
                ignored = !rule.negated;
            }
        }

        ignored
    }
}

impl FromStr for IgnoreList {
    type Err = BulkHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn path_to_segments(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn strip_trailing_unescaped_spaces(input: &str) -> &str {
    let bytes = input.as_bytes();
    let mut end = bytes.len();

    while end > 0 && bytes.get(end - 1) == Some(&b' ') {
        let mut backslashes = 0usize;
        let mut idx = end - 1;
        while idx > 0 && bytes.get(idx - 1) == Some(&b'\\') {
            backslashes += 1;
            idx -= 1;
        }
        if backslashes % 2 == 1 {
            break;
        }
        end -= 1;
    }

    input.get(..end).unwrap_or("")
}

fn compile_rule(raw_line: &str) -> Result<Option<(String, CompiledRule)>, BulkHashError> {
    let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
    let cleaned = strip_trailing_unescaped_spaces(line);

    if cleaned.is_empty() || (!cleaned.contains('\\') && cleaned.trim().is_empty()) {
        return Ok(None);
    }

    if cleaned.starts_with('#') {
        return Ok(None);
    }

    let stored_pattern = cleaned.to_string();

    let (negated, mut rest) = if let Some(stripped) = cleaned.strip_prefix('!') {
        (true, stripped)
    } else {
        (false, cleaned)
    };

    if rest.is_empty() {
        return Err(BulkHashError::InvalidIgnorePattern {
            pattern: stored_pattern,
            reason: String::from("Negated pattern cannot be empty"),
        });
    }

    let mut anchored = false;
    loop {
        if let Some(stripped) = rest.strip_prefix('/') {
            anchored = true;
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix("./") {
            anchored = true;
            rest = stripped;
        } else {
            break;
        }
    }

    let mut dir_only = false;
    while let Some(stripped) = rest.strip_suffix('/') {
        dir_only = true;
        rest = stripped;
    }

    if rest.is_empty() {
        return Err(BulkHashError::InvalidIgnorePattern {
            pattern: stored_pattern,
            reason: String::from("Pattern contains no path or filename component"),
        });
    }

    if rest.contains('/') {
        anchored = true;
    }

    let mut segments: Vec<Segment> = Vec::new();
    for raw_seg in rest.split('/') {
        if raw_seg.is_empty() {
            continue;
        }
        let segment = if raw_seg == "**" {
            Segment::DoubleStar
        } else {
            Segment::Glob(parse_glob_segment(raw_seg, &stored_pattern)?)
        };

        if matches!(segment, Segment::DoubleStar)
            && matches!(segments.last(), Some(Segment::DoubleStar))
        {
            continue;
        }
        segments.push(segment);
    }

    if segments.is_empty() {
        return Err(BulkHashError::InvalidIgnorePattern {
            pattern: stored_pattern,
            reason: String::from("Pattern contains no path or filename component"),
        });
    }

    // Trailing `/**` (e.g. `foo/**`) matches everything *inside* `foo`, not `foo` itself.
    // Equivalent to requiring at least one segment after the prefix: `foo/*/**`.
    if segments.len() > 1 && matches!(segments.last(), Some(Segment::DoubleStar)) {
        segments.pop();
        segments.push(Segment::Glob(vec![GlobToken::AnySeq]));
        segments.push(Segment::DoubleStar);
    }

    Ok(Some((
        stored_pattern,
        CompiledRule {
            negated,
            dir_only,
            anchored,
            segments,
        },
    )))
}

fn parse_glob_segment(seg: &str, full_pattern: &str) -> Result<Vec<GlobToken>, BulkHashError> {
    let mut tokens = Vec::new();
    let mut chars = seg.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let escaped = chars
                    .next()
                    .ok_or_else(|| BulkHashError::InvalidIgnorePattern {
                        pattern: full_pattern.to_string(),
                        reason: String::from("Trailing unescaped backslash"),
                    })?;
                tokens.push(GlobToken::Literal(escaped));
            }
            '*' => {
                if !matches!(tokens.last(), Some(GlobToken::AnySeq)) {
                    tokens.push(GlobToken::AnySeq);
                }
            }
            '?' => tokens.push(GlobToken::AnyChar),
            '[' => {
                let class_token = parse_char_class(&mut chars, full_pattern)?;
                tokens.push(class_token);
            }
            literal => tokens.push(GlobToken::Literal(literal)),
        }
    }

    Ok(tokens)
}

fn parse_char_class(
    chars: &mut std::str::Chars<'_>,
    full_pattern: &str,
) -> Result<GlobToken, BulkHashError> {
    let mut negated = false;
    let mut peek = chars.clone();
    if matches!(peek.next(), Some('!' | '^')) {
        negated = true;
        let _ = chars.next();
    }

    let mut items = Vec::new();
    let mut first = true;

    loop {
        let Some(raw) = chars.next() else {
            return Err(BulkHashError::InvalidIgnorePattern {
                pattern: full_pattern.to_string(),
                reason: String::from("Unclosed character class '['"),
            });
        };

        if raw == ']' && !first {
            break;
        }

        let start_char = if raw == '\\' {
            chars
                .next()
                .ok_or_else(|| BulkHashError::InvalidIgnorePattern {
                    pattern: full_pattern.to_string(),
                    reason: String::from("Trailing backslash inside character class"),
                })?
        } else {
            raw
        };
        first = false;

        let mut lookahead = chars.clone();
        if lookahead.next() == Some('-') {
            match lookahead.next() {
                Some(']') | None => {
                    items.push(CharClassItem::Single(start_char));
                }
                Some(end_raw) => {
                    let _ = chars.next(); // consume '-'
                    let end_char = if end_raw == '\\' {
                        let _ = chars.next(); // consume '\\'
                        chars
                            .next()
                            .ok_or_else(|| BulkHashError::InvalidIgnorePattern {
                                pattern: full_pattern.to_string(),
                                reason: String::from("Trailing backslash inside character class"),
                            })?
                    } else {
                        let _ = chars.next(); // consume end_raw
                        end_raw
                    };

                    if start_char > end_char {
                        return Err(BulkHashError::InvalidIgnorePattern {
                            pattern: full_pattern.to_string(),
                            reason: format!("Invalid character range '{start_char}-{end_char}'"),
                        });
                    }

                    items.push(CharClassItem::Range(start_char, end_char));
                }
            }
        } else {
            items.push(CharClassItem::Single(start_char));
        }
    }

    Ok(GlobToken::CharClass { negated, items })
}

fn match_segments(
    pattern_segs: &[Segment],
    path_segs: PathSegments<'_>,
    case_insensitive: bool,
) -> bool {
    let mut pat_idx = 0usize;
    let mut path_idx = 0usize;
    let mut star_pat_idx: Option<usize> = None;
    let mut star_path_idx = 0usize;

    while path_idx < path_segs.len() {
        if let Some(pat_seg) = pattern_segs.get(pat_idx) {
            match pat_seg {
                Segment::DoubleStar => {
                    star_pat_idx = Some(pat_idx);
                    star_path_idx = path_idx;
                    pat_idx += 1;
                    continue;
                }
                Segment::Glob(tokens) => {
                    if let Some(seg) = path_segs.get(path_idx)
                        && match_segment(tokens, seg, case_insensitive)
                    {
                        pat_idx += 1;
                        path_idx += 1;
                        continue;
                    }
                }
            }
        }

        if let Some(saved_pat_idx) = star_pat_idx {
            star_path_idx += 1;
            path_idx = star_path_idx;
            pat_idx = saved_pat_idx + 1;
            continue;
        }

        return false;
    }

    while matches!(pattern_segs.get(pat_idx), Some(Segment::DoubleStar)) {
        pat_idx += 1;
    }

    pat_idx == pattern_segs.len()
}

fn match_segment(tokens: &[GlobToken], text: &str, case_insensitive: bool) -> bool {
    let mut token_idx = 0usize;
    let mut byte_idx = 0usize;
    let mut star_token_idx: Option<usize> = None;
    let mut star_byte_idx = 0usize;
    let bytes_len = text.len();

    while byte_idx < bytes_len {
        if let Some(token) = tokens.get(token_idx) {
            match token {
                GlobToken::AnySeq => {
                    star_token_idx = Some(token_idx);
                    star_byte_idx = byte_idx;
                    token_idx += 1;
                    continue;
                }
                _ => {
                    if let Some(ch) = text.get(byte_idx..).and_then(|s| s.chars().next())
                        && token_matches_char(token, ch, case_insensitive)
                    {
                        token_idx += 1;
                        byte_idx += ch.len_utf8();
                        continue;
                    }
                }
            }
        }

        if let Some(saved_token_idx) = star_token_idx
            && let Some(ch) = text.get(star_byte_idx..).and_then(|s| s.chars().next())
        {
            star_byte_idx += ch.len_utf8();
            byte_idx = star_byte_idx;
            token_idx = saved_token_idx + 1;
            continue;
        }

        return false;
    }

    while matches!(tokens.get(token_idx), Some(GlobToken::AnySeq)) {
        token_idx += 1;
    }

    token_idx == tokens.len()
}

fn token_matches_char(token: &GlobToken, ch: char, case_insensitive: bool) -> bool {
    match token {
        GlobToken::Literal(expected) => chars_eq(ch, *expected, case_insensitive),
        GlobToken::AnyChar | GlobToken::AnySeq => true,
        GlobToken::CharClass { negated, items } => {
            let matched = items
                .iter()
                .any(|item| char_class_item_matches(item, ch, case_insensitive));
            if *negated { !matched } else { matched }
        }
    }
}

fn chars_eq(a: char, b: char, case_insensitive: bool) -> bool {
    if a == b {
        return true;
    }
    if !case_insensitive {
        return false;
    }
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(&b);
    }
    a.to_lowercase().eq(b.to_lowercase())
}

fn char_class_item_matches(item: &CharClassItem, ch: char, case_insensitive: bool) -> bool {
    match item {
        CharClassItem::Single(expected) => chars_eq(ch, *expected, case_insensitive),
        CharClassItem::Range(start, end) => {
            if ch >= *start && ch <= *end {
                return true;
            }
            if !case_insensitive {
                return false;
            }
            single_folded_char(ch.to_lowercase()).is_some_and(|c| c >= *start && c <= *end)
                || single_folded_char(ch.to_uppercase()).is_some_and(|c| c >= *start && c <= *end)
        }
    }
}

fn single_folded_char<I: Iterator<Item = char>>(mut iter: I) -> Option<char> {
    let first = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    Some(first)
}
