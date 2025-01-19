use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{fmt, num::NonZeroU32, ops::Range};

use super::{FileLineCol, SourceId, SourceSpan};

// SOURCE FILE
// ================================================================================================

/// A [SourceFile] represents a single file stored in a [super::SourceManager]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceFile {
    /// The unique identifier allocated for this [SourceFile] by its owning [super::SourceManager]
    id: SourceId,
    /// The file content
    content: SourceContent,
}

#[cfg(feature = "diagnostics")]
impl miette::SourceCode for SourceFile {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<alloc::boxed::Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        let mut start =
            u32::try_from(span.offset()).map_err(|_| miette::MietteError::OutOfBounds)?;
        let len = u32::try_from(span.len()).map_err(|_| miette::MietteError::OutOfBounds)?;
        let mut end = start.checked_add(len).ok_or(miette::MietteError::OutOfBounds)?;
        if context_lines_before > 0 {
            let line_index = self.content.line_index(start.into());
            let start_line_index = line_index.saturating_sub(context_lines_before as u32);
            start = self.content.line_start(start_line_index).map(|idx| idx.to_u32()).unwrap_or(0);
        }
        if context_lines_after > 0 {
            let line_index = self.content.line_index(end.into());
            let end_line_index = line_index
                .checked_add(context_lines_after as u32)
                .ok_or(miette::MietteError::OutOfBounds)?;
            end = self
                .content
                .line_range(end_line_index)
                .map(|range| range.end.to_u32())
                .unwrap_or_else(|| self.content.source_range().end.to_u32());
        }
        Ok(Box::new(ScopedSourceFileRef {
            file: self,
            span: miette::SourceSpan::new((start as usize).into(), end.abs_diff(start) as usize),
        }))
    }
}

impl SourceFile {
    /// Create a new [SourceFile] from its raw components
    pub fn new(id: SourceId, path: impl Into<Arc<str>>, content: impl Into<Box<str>>) -> Self {
        let path = path.into();
        let content = SourceContent::new(path, content.into());
        Self { id, content }
    }

    pub(super) fn from_raw_parts(id: SourceId, content: SourceContent) -> Self {
        Self { id, content }
    }

    /// Get the [SourceId] associated with this file
    pub const fn id(&self) -> SourceId {
        self.id
    }

    /// Get the name of this source file
    pub fn name(&self) -> Arc<str> {
        self.content.name()
    }

    /// Get the path of this source file as a [std::path::Path]
    #[cfg(feature = "std")]
    #[inline]
    pub fn path(&self) -> &std::path::Path {
        self.content.path()
    }

    /// Returns a reference to the underlying [SourceContent]
    pub fn content(&self) -> &SourceContent {
        &self.content
    }

    /// Returns the number of lines in this file
    pub fn line_count(&self) -> usize {
        self.content.last_line_index().to_usize() + 1
    }

    /// Returns the number of bytes in this file
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns true if this file is empty
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Get the underlying content of this file
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.content.as_str()
    }

    /// Get the underlying content of this file as a byte slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    /// Returns a [SourceSpan] covering the entirety of this file
    #[inline]
    pub fn source_span(&self) -> SourceSpan {
        let range = self.content.source_range();
        SourceSpan::new(self.id, range.start.0..range.end.0)
    }

    /// Returns a subset of the underlying content as a string slice.
    ///
    /// The bounds of the given span are character indices, _not_ byte indices.
    ///
    /// Returns `None` if the given span is out of bounds
    #[inline(always)]
    pub fn source_slice(&self, span: impl Into<Range<usize>>) -> Option<&str> {
        self.content.source_slice(span)
    }

    /// Returns a [SourceFileRef] corresponding to the bytes contained in the specified span.
    pub fn slice(self: &Arc<Self>, span: impl Into<Range<u32>>) -> SourceFileRef {
        SourceFileRef::new(Arc::clone(self), span)
    }

    /// Get a [SourceSpan] which points to the first byte of the character at `column` on `line`
    ///
    /// Returns `None` if the given line/column is out of bounds for this file.
    pub fn line_column_to_span(&self, line: u32, column: u32) -> Option<SourceSpan> {
        let line_index = LineIndex::from(line.saturating_sub(1));
        let column_index = ColumnIndex::from(column.saturating_sub(1));
        let offset = self.content.line_column_to_offset(line_index, column_index)?;
        Some(SourceSpan::at(self.id, offset.0))
    }

    /// Get a [FileLineCol] equivalent to the start of the given [SourceSpan]
    pub fn location(&self, span: SourceSpan) -> FileLineCol {
        assert_eq!(span.source_id(), self.id, "mismatched source ids");

        self.content
            .location(ByteIndex(span.into_range().start))
            .expect("invalid source span: starting byte is out of bounds")
    }
}

impl AsRef<str> for SourceFile {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SourceFile {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "std")]
impl AsRef<std::path::Path> for SourceFile {
    #[inline(always)]
    fn as_ref(&self) -> &std::path::Path {
        self.path()
    }
}

// SOURCE FILE REF
// ================================================================================================

/// A reference to a specific spanned region of a [SourceFile], that provides access to the actual
/// [SourceFile], but scoped to the span it was created with.
///
/// This is useful in error types that implement [miette::Diagnostic], as it contains all of the
/// data necessary to render the source code being referenced, without a [super::SourceManager] on
/// hand.
#[derive(Debug, Clone)]
pub struct SourceFileRef {
    file: Arc<SourceFile>,
    span: SourceSpan,
}

impl SourceFileRef {
    /// Create a [SourceFileRef] from a [SourceFile] and desired span (in bytes)
    ///
    /// The given span will be constrained to the bytes of `file`, so a span that reaches out of
    /// bounds will have its end bound set to the last byte of the file.
    pub fn new(file: Arc<SourceFile>, span: impl Into<Range<u32>>) -> Self {
        let span = span.into();
        let end = core::cmp::min(span.end, file.len() as u32);
        let span = SourceSpan::new(file.id(), span.start..end);
        Self { file, span }
    }

    /// Returns a ref-counted handle to the underlying [SourceFile]
    pub fn source_file(&self) -> Arc<SourceFile> {
        self.file.clone()
    }

    /// Returns the name of the file this [SourceFileRef] is selecting, as a [std::path::Path]
    #[cfg(feature = "std")]
    pub fn path(&self) -> &std::path::Path {
        self.file.path()
    }

    /// Returns the name of the file this [SourceFileRef] is selecting
    pub fn name(&self) -> &str {
        self.file.content.path.as_ref()
    }

    /// Returns the [SourceSpan] selected by this [SourceFileRef]
    pub const fn span(&self) -> SourceSpan {
        self.span
    }

    /// Returns the underlying `str` selected by this [SourceFileRef]
    pub fn as_str(&self) -> &str {
        self.file.source_slice(self.span).unwrap()
    }

    /// Returns the underlying bytes selected by this [SourceFileRef]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the number of bytes represented by the subset of the underlying file that is covered
    /// by this [SourceFileRef]
    pub fn len(&self) -> usize {
        self.span.len()
    }

    /// Returns true if this selection is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Eq for SourceFileRef {}

impl PartialEq for SourceFileRef {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Ord for SourceFileRef {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for SourceFileRef {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for SourceFileRef {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.span.hash(state);
        self.as_str().hash(state);
    }
}

impl AsRef<str> for SourceFileRef {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SourceFileRef {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "diagnostics")]
impl From<&SourceFileRef> for miette::SourceSpan {
    fn from(source: &SourceFileRef) -> Self {
        source.span.into()
    }
}

/// Used to implement [miette::SpanContents] for [SourceFile] and [SourceFileRef]
#[cfg(feature = "diagnostics")]
struct ScopedSourceFileRef<'a> {
    file: &'a SourceFile,
    span: miette::SourceSpan,
}

#[cfg(feature = "diagnostics")]
impl<'a> miette::SpanContents<'a> for ScopedSourceFileRef<'a> {
    #[inline]
    fn data(&self) -> &'a [u8] {
        let start = self.span.offset();
        let end = start + self.span.len();
        &self.file.as_bytes()[start..end]
    }

    #[inline]
    fn span(&self) -> &miette::SourceSpan {
        &self.span
    }

    fn line(&self) -> usize {
        let offset = self.span.offset() as u32;
        self.file.content.line_index(offset.into()).to_usize()
    }

    fn column(&self) -> usize {
        let start = self.span.offset() as u32;
        let end = start + self.span.len() as u32;
        let span = SourceSpan::new(self.file.id(), start..end);
        let loc = self.file.location(span);
        loc.column.saturating_sub(1) as usize
    }

    #[inline]
    fn line_count(&self) -> usize {
        self.file.line_count()
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        Some(self.file.content.path.as_ref())
    }

    #[inline]
    fn language(&self) -> Option<&str> {
        None
    }
}

#[cfg(feature = "diagnostics")]
impl miette::SourceCode for SourceFileRef {
    #[inline]
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<alloc::boxed::Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.file.read_span(span, context_lines_before, context_lines_after)
    }
}

// SOURCE CONTENT
// ================================================================================================

/// Represents key information about a source file and its content:
///
/// * The path to the file (or its name, in the case of virtual files)
/// * The content of the file
/// * The byte offsets of every line in the file, for use in looking up line/column information
#[derive(Clone)]
pub struct SourceContent {
    /// The path (or name) of this file
    path: Arc<str>,
    /// The underlying content of this file
    content: Box<str>,
    /// The byte offsets for each line in this file
    line_starts: Box<[ByteIndex]>,
}

impl fmt::Debug for SourceContent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SourceContent")
            .field("path", &self.path)
            .field("size_in_bytes", &self.content.len())
            .field("line_count", &self.line_starts.len())
            .field("content", &self.content)
            .finish()
    }
}

impl Eq for SourceContent {}

impl PartialEq for SourceContent {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.content == other.content
    }
}

impl Ord for SourceContent {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.path.cmp(&other.path).then_with(|| self.content.cmp(&other.content))
    }
}

impl PartialOrd for SourceContent {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for SourceContent {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.content.hash(state);
    }
}

impl SourceContent {
    /// Create a new [SourceContent] from the (possibly virtual) file path, and its content as a
    /// UTF-8 string.
    ///
    /// When created, the line starts for this file will be computed, which requires scanning the
    /// file content once.
    pub fn new(path: Arc<str>, content: Box<str>) -> Self {
        let bytes = content.as_bytes();

        assert!(
            bytes.len() < u32::MAX as usize,
            "unsupported source file: current maximum supported length in bytes is 2^32"
        );

        let line_starts = core::iter::once(ByteIndex(0))
            .chain(memchr::memchr_iter(b'\n', content.as_bytes()).filter_map(|mut offset| {
                // Determine if the newline has any preceding escapes
                let mut preceding_escapes = 0;
                let line_start = offset + 1;
                while let Some(prev_offset) = offset.checked_sub(1) {
                    if bytes[prev_offset] == b'\\' {
                        offset = prev_offset;
                        preceding_escapes += 1;
                        continue;
                    }
                    break;
                }

                // If the newline is escaped, do not count it as a new line
                let is_escaped = preceding_escapes > 0 && preceding_escapes % 2 != 0;
                if is_escaped {
                    None
                } else {
                    Some(ByteIndex(line_start as u32))
                }
            }))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self { path, content, line_starts }
    }

    /// Get the name of this source file
    pub fn name(&self) -> Arc<str> {
        self.path.clone()
    }

    /// Get the name of this source file as a [std::path::Path]
    #[cfg(feature = "std")]
    #[inline]
    pub fn path(&self) -> &std::path::Path {
        std::path::Path::new(self.path.as_ref())
    }

    /// Returns the underlying content as a string slice
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.content.as_ref()
    }

    /// Returns the underlying content as a byte slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    /// Returns the size in bytes of the underlying content
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns true if the underlying content is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Returns the range of valid byte indices for this file
    #[inline]
    pub fn source_range(&self) -> Range<ByteIndex> {
        ByteIndex(0)..ByteIndex(self.content.len() as u32)
    }

    /// Returns a subset of the underlying content as a string slice.
    ///
    /// The bounds of the given span are character indices, _not_ byte indices.
    ///
    /// Returns `None` if the given span is out of bounds
    #[inline(always)]
    pub fn source_slice(&self, span: impl Into<Range<usize>>) -> Option<&str> {
        self.as_str().get(span.into())
    }

    /// Returns the byte index at which the line corresponding to `line_index` starts
    ///
    /// Returns `None` if the given index is out of bounds
    pub fn line_start(&self, line_index: LineIndex) -> Option<ByteIndex> {
        self.line_starts.get(line_index.to_usize()).copied()
    }

    /// Returns the index of the last line in this file
    #[inline]
    pub fn last_line_index(&self) -> LineIndex {
        LineIndex(self.line_starts.len() as u32)
    }

    /// Get the range of byte indices covered by the given line
    pub fn line_range(&self, line_index: LineIndex) -> Option<Range<ByteIndex>> {
        let line_start = self.line_start(line_index)?;
        match self.line_start(line_index + 1) {
            Some(line_end) => Some(line_start..line_end),
            None => Some(line_start..ByteIndex(self.content.len() as u32)),
        }
    }

    /// Get the index of the line to which `byte_index` belongs
    pub fn line_index(&self, byte_index: ByteIndex) -> LineIndex {
        match self.line_starts.binary_search(&byte_index) {
            Ok(line) => LineIndex(line as u32),
            Err(next_line) => LineIndex(next_line as u32 - 1),
        }
    }

    /// Get the [ByteIndex] corresponding to the given line and column indices.
    ///
    /// Returns `None` if the line or column indices are out of bounds.
    pub fn line_column_to_offset(
        &self,
        line_index: LineIndex,
        column_index: ColumnIndex,
    ) -> Option<ByteIndex> {
        let column_index = column_index.to_usize();
        let line_span = self.line_range(line_index)?;
        let line_src = self
            .content
            .get(line_span.start.to_usize()..line_span.end.to_usize())
            .expect("invalid line boundaries: invalid utf-8");
        if line_src.len() < column_index {
            return None;
        }
        let (pre, _) = line_src.split_at(column_index);
        let start = line_span.start;
        Some(start + ByteOffset::from_str_len(pre))
    }

    /// Get a [FileLineCol] corresponding to the line/column in this file at which `byte_index`
    /// occurs
    pub fn location(&self, byte_index: ByteIndex) -> Option<FileLineCol> {
        let line_index = self.line_index(byte_index);
        let line_start_index = self.line_start(line_index)?;
        let line_src = self.content.get(line_start_index.to_usize()..byte_index.to_usize())?;
        let column_index = ColumnIndex::from(line_src.chars().count() as u32);
        Some(FileLineCol {
            path: self.path.clone(),
            line: line_index.number().get(),
            column: column_index.number().get(),
        })
    }
}

// SOURCE CONTENT INDICES
// ================================================================================================

/// An index representing the offset in bytes from the start of a source file
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteIndex(u32);
impl ByteIndex {
    /// Create a [ByteIndex] from a raw `u32` index
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Get the raw index as a usize
    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    /// Get the raw index as a u32
    #[inline(always)]
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}
impl core::ops::Add<ByteOffset> for ByteIndex {
    type Output = ByteIndex;

    fn add(self, rhs: ByteOffset) -> Self {
        Self((self.0 as i64 + rhs.0) as u32)
    }
}
impl core::ops::Add<u32> for ByteIndex {
    type Output = ByteIndex;

    fn add(self, rhs: u32) -> Self {
        Self(self.0 + rhs)
    }
}
impl core::ops::AddAssign<ByteOffset> for ByteIndex {
    fn add_assign(&mut self, rhs: ByteOffset) {
        *self = *self + rhs;
    }
}
impl core::ops::AddAssign<u32> for ByteIndex {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}
impl core::ops::Sub<ByteOffset> for ByteIndex {
    type Output = ByteIndex;

    fn sub(self, rhs: ByteOffset) -> Self {
        Self((self.0 as i64 - rhs.0) as u32)
    }
}
impl core::ops::Sub<u32> for ByteIndex {
    type Output = ByteIndex;

    fn sub(self, rhs: u32) -> Self {
        Self(self.0 - rhs)
    }
}
impl core::ops::SubAssign<ByteOffset> for ByteIndex {
    fn sub_assign(&mut self, rhs: ByteOffset) {
        *self = *self - rhs;
    }
}
impl core::ops::SubAssign<u32> for ByteIndex {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 -= rhs;
    }
}
impl From<u32> for ByteIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}
impl From<ByteIndex> for u32 {
    fn from(index: ByteIndex) -> Self {
        index.0
    }
}

/// An offset in bytes relative to some [ByteIndex]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteOffset(i64);
impl ByteOffset {
    /// Compute the offset in bytes represented by the given `char`
    pub fn from_char_len(c: char) -> ByteOffset {
        Self(c.len_utf8() as i64)
    }

    /// Compute the offset in bytes represented by the given `str`
    pub fn from_str_len(s: &str) -> ByteOffset {
        Self(s.len() as i64)
    }
}
impl core::ops::Add for ByteOffset {
    type Output = ByteOffset;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}
impl core::ops::AddAssign for ByteOffset {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}
impl core::ops::Sub for ByteOffset {
    type Output = ByteOffset;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}
impl core::ops::SubAssign for ByteOffset {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

/// A zero-indexed line number
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LineIndex(u32);
impl LineIndex {
    /// Get a one-indexed number for display
    pub const fn number(self) -> NonZeroU32 {
        unsafe { NonZeroU32::new_unchecked(self.0 + 1) }
    }

    /// Get the raw index as a usize
    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    /// Add `offset` to this index, returning `None` on overflow
    pub fn checked_add(self, offset: u32) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    /// Subtract `offset` from this index, returning `None` on underflow
    pub fn checked_sub(self, offset: u32) -> Option<Self> {
        self.0.checked_sub(offset).map(Self)
    }

    /// Add `offset` to this index, saturating to `u32::MAX` on overflow
    pub const fn saturating_add(self, offset: u32) -> Self {
        Self(self.0.saturating_add(offset))
    }

    /// Subtract `offset` from this index, saturating to `0` on overflow
    pub const fn saturating_sub(self, offset: u32) -> Self {
        Self(self.0.saturating_sub(offset))
    }
}
impl From<u32> for LineIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}
impl core::ops::Add<u32> for LineIndex {
    type Output = LineIndex;

    fn add(self, rhs: u32) -> Self {
        Self(self.0 + rhs)
    }
}

/// A zero-indexed column number
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ColumnIndex(u32);
impl ColumnIndex {
    /// Get a one-indexed number for display
    pub const fn number(self) -> NonZeroU32 {
        unsafe { NonZeroU32::new_unchecked(self.0 + 1) }
    }

    /// Get the raw index as a usize
    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }
}
impl From<u32> for ColumnIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}
