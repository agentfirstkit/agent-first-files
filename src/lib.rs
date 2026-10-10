//! A root-locked, read-only projection of one directory tree.
//!
//! The consumer is a person who is not at this machine. An agent working here
//! already has `ls`, a file reader and a grep; what it has no way to do is put
//! a working directory in front of somebody holding a phone. So this is not a
//! filesystem API with a UI attached — it is a projection of one subtree, and
//! every decision below follows from that being reachable over a URL.
//!
//! # The root is the boundary
//!
//! One process, one root, fixed when [`FileRoot::open`] returns. Every path a
//! caller supplies is relative to it, and the upper bound on what a leaked URL
//! can show is the root itself. That makes choosing the root the security
//! decision, which is why it has no default: a convenient "current directory"
//! becomes a home directory the moment somebody runs this after `cd ~`.
//!
//! Three rules keep a path inside it, and each exists because of a specific way
//! the obvious version fails.
//!
//! 1. **Comparison is by path component, never by string prefix.** `/srv/root`
//!    is a prefix of `/srv/root-evil` as text and not as a path.
//! 2. **Containment is checked after canonicalization**, so an intermediate
//!    symlink cannot smuggle a path out of the root before the last component
//!    is even looked at.
//! 3. **Refusals are `NotFound`.** An error that distinguishes "excluded" or
//!    "outside the root" from "not there" is an oracle for what exists.
//!
//! # What this does not do
//!
//! It does not write. It does not redact file contents — that is the person's
//! own data and scrubbing it would corrupt the thing they came to read; only
//! this crate's own envelope fields go through AFDATA redaction, at the HTTP
//! boundary. It does not carry a built-in list of dangerous filenames, because
//! one that misses `.env.local.bak` is worse than none: [`FileRootConfig`]
//! takes the caller's own patterns and the root does the rest.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

/// How many bytes one read returns when the caller does not say.
pub const DEFAULT_MAX_READ_BYTES: u64 = 1024 * 1024;

/// How many entries one listing returns when the caller does not say, and the
/// most it will return however loudly they ask.
pub const DEFAULT_PAGE_LIMIT: usize = 500;
pub const MAX_PAGE_LIMIT: usize = 2000;

/// Public cursors are opaque strings, but the ordering key is a filename's raw
/// bytes. Encoding the key keeps paging exact even when a directory contains a
/// name that cannot make a UTF-8 round trip through JSON.
const CURSOR_PREFIX: &str = "name-bytes:";

/// How much of a file is examined before calling it text or bytes.
const SNIFF_BYTES: usize = 8 * 1024;

/// What a caller asked for that could not be given.
///
/// Deliberately without an "excluded" or "escaped the root" variant. Both are
/// [`Self::NotFound`], because an error that can tell them apart tells a caller
/// that something is there.
#[derive(Debug)]
pub enum FilesError {
    /// No such entry, or one this projection does not offer. Both, on purpose.
    NotFound,
    NotADirectory,
    IsADirectory,
    /// Readable, but not as text: it has bytes in it that no text has.
    NotText,
    /// The path is not one this projection can accept at all — absolute, or
    /// climbing out with `..`, or carrying a byte a path may not.
    InvalidPath(&'static str),
    /// A paging cursor carrying the projection's prefix but not its encoding.
    InvalidCursor,
    /// An exclude pattern written in a grammar this matcher does not implement.
    ///
    /// Refused rather than matched literally. An exclusion is what keeps a
    /// credential out of a listing, and a pattern that looks like it works and
    /// does not is worse than no pattern at all — the person believes the file
    /// is hidden.
    InvalidExclude {
        /// The pattern as written.
        pattern: String,
        /// Which construct it used, and what to write instead.
        reason: &'static str,
    },
    /// More directories than one viewer may watch at once.
    TooManyWatches {
        /// How many the caller asked for.
        requested: usize,
        /// The ceiling, which no request or configuration can raise.
        limit: usize,
    },
    /// The operating system refused a watch registration.
    ///
    /// Nothing was changed: the set this process is watching is the set it was
    /// watching before the call.
    WatchRegistrationFailed,
    PermissionDenied,
    Io(std::io::Error),
}

impl std::fmt::Display for FilesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("no such entry under this root"),
            Self::NotADirectory => formatter.write_str("that path is not a directory"),
            Self::IsADirectory => formatter.write_str("that path is a directory"),
            Self::NotText => formatter.write_str("that file is not text"),
            Self::InvalidPath(reason) => write!(formatter, "invalid path: {reason}"),
            Self::InvalidCursor => formatter.write_str("invalid directory cursor"),
            Self::InvalidExclude { pattern, reason } => {
                write!(
                    formatter,
                    "unsupported exclude pattern `{pattern}`: {reason}"
                )
            }
            Self::TooManyWatches { requested, limit } => write!(
                formatter,
                "{requested} directories is more than the {limit} this view may watch at once"
            ),
            Self::WatchRegistrationFailed => {
                formatter.write_str("the directories shown by this view could not be watched")
            }
            Self::PermissionDenied => formatter.write_str("this process may not read that entry"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for FilesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FilesError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Io(error),
        }
    }
}

pub type Result<T> = std::result::Result<T, FilesError>;

/// What a symlink is allowed to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymlinkPolicy {
    /// Follow a link whose target is inside the root, and refuse one whose
    /// target is not.
    ///
    /// The default, because both extremes are wrong in practice. Refusing every
    /// link makes an ordinary source tree unbrowsable — `node_modules/.bin` and
    /// monorepo cross-links are links. Following every link deletes the root
    /// boundary the first time somebody has a link to `/` or to `~/.ssh`.
    #[default]
    WithinRoot,
    /// Follow nothing. No component of a path may be a link, checked component
    /// by component rather than guessed at from the resolved result.
    Never,
}

/// Everything a projection is, before it exists.
#[derive(Debug, Clone)]
pub struct FileRootConfig {
    /// The one directory this projection offers. No default: see the module
    /// documentation.
    pub root: PathBuf,
    /// Patterns whose matches do not appear at all.
    ///
    /// Gitignore's convention, because it is the one people already know: a
    /// pattern with no `/` matches an entry's name at any depth (`*.pem`), and
    /// one with a `/` matches the whole root-relative path (`secrets/**`).
    ///
    /// A match is absent from listings rather than present-but-refused. Being
    /// listed is itself disclosure — the name `payroll-2026/` says plenty
    /// before anybody opens it.
    pub exclude: Vec<String>,
    pub symlinks: SymlinkPolicy,
    /// The ceiling on one read, whatever a request asks for.
    pub max_read_bytes: u64,
}

impl FileRootConfig {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            exclude: Vec::new(),
            symlinks: SymlinkPolicy::default(),
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
        }
    }

    #[must_use]
    pub fn with_exclude(mut self, patterns: impl IntoIterator<Item = String>) -> Self {
        self.exclude.extend(patterns);
        self
    }

    #[must_use]
    pub fn with_symlinks(mut self, symlinks: SymlinkPolicy) -> Self {
        self.symlinks = symlinks;
        self
    }

    #[must_use]
    pub fn with_max_read_bytes(mut self, max_read_bytes: u64) -> Self {
        self.max_read_bytes = max_read_bytes;
        self
    }
}

#[cfg(feature = "watch")]
mod watch;

#[cfg(feature = "watch")]
pub use watch::{RootWatcher, WatchEvent};

/// One root, and the only way to reach anything under it.
#[derive(Debug)]
pub struct FileRoot {
    root: PathBuf,
    exclude: Vec<String>,
    symlinks: SymlinkPolicy,
    max_read_bytes: u64,
}

/// A path this projection has already accepted.
///
/// Constructed only by [`RelPath::parse`], so "a path nobody validated" is not
/// a thing that exists here — the check cannot be forgotten at a call site
/// because there is no way to produce the type without it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelPath(String);

impl RelPath {
    /// The root itself.
    #[must_use]
    pub fn root() -> Self {
        Self(String::new())
    }

    /// Accept a caller's path, or say why not.
    ///
    /// `.` and empty segments are dropped, `..` is refused rather than
    /// resolved, and the result is spelled one way — so two spellings of one
    /// path cannot become two cache keys, two exclusion decisions, or two
    /// answers.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.contains('\0') {
            return Err(FilesError::InvalidPath("a path may not contain a NUL"));
        }
        let candidate = Path::new(raw);
        let mut parts = Vec::new();
        for component in candidate.components() {
            match component {
                Component::Normal(part) => match part.to_str() {
                    Some(part) => parts.push(part),
                    None => {
                        return Err(FilesError::InvalidPath("a path segment is not valid UTF-8"));
                    }
                },
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(FilesError::InvalidPath(
                        "`..` climbs out of the root, so it is never resolved",
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(FilesError::InvalidPath(
                        "paths are relative to the root; an absolute one names something else",
                    ));
                }
            }
        }
        Ok(Self(parts.join("/")))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The last segment, which is what an entry is called.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or("")
    }

    fn child(&self, name: &str) -> Self {
        if self.0.is_empty() {
            Self(name.to_owned())
        } else {
            Self(format!("{}/{name}", self.0))
        }
    }
}

/// What kind of thing an entry is, as far as a listing needs to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    /// A socket, a device, a fifo — real, named, and not something to open.
    Other,
}

impl EntryKind {
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

/// Why an entry that exists cannot be used the ordinary way.
///
/// Said out loud rather than hidden. "There is something here you cannot open"
/// and "there is nothing here" are different facts, and a browser that silently
/// dropped the first would be quietly lying about the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// A name that is not UTF-8. Listed, because a person should see that the
    /// directory is not empty; unopenable, because the name cannot survive the
    /// round trip through a JSON string that reaching it would need.
    NonUtf8Name,
    /// A link that leaves the root. Named, never followed.
    OutsideRoot,
    /// Neither a file nor a directory.
    UnsupportedKind,
}

impl Unsupported {
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::NonUtf8Name => "non_utf8_name",
            Self::OutsideRoot => "outside_root",
            Self::UnsupportedKind => "unsupported_kind",
        }
    }
}

/// One entry, as a listing describes it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Root-relative, and the key for every later call about this entry.
    pub path: String,
    pub name: String,
    pub kind: EntryKind,
    pub size_bytes: u64,
    pub modified_rfc3339: Option<String>,
    pub readable: bool,
    pub unsupported: Option<Unsupported>,
    /// Where a link points, as written. Advisory: it is shown, never resolved
    /// on the caller's behalf.
    pub symlink_target: Option<String>,
}

/// What a caller wants of a long directory.
#[derive(Debug, Clone)]
pub struct Page {
    pub limit: usize,
    /// The ordering key to resume after. Opaque to a caller, and only ever a
    /// cursor this projection handed out.
    pub cursor: Option<String>,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            cursor: None,
        }
    }
}

/// One directory, in the order it is always in.
#[derive(Debug, Clone)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
    /// `None` once the directory is exhausted.
    pub next_cursor: Option<String>,
}

/// Which slice of a file to read.
#[derive(Debug, Clone, Copy)]
pub struct ByteWindow {
    pub offset_bytes: u64,
    pub max_bytes: u64,
}

impl Default for ByteWindow {
    fn default() -> Self {
        Self {
            offset_bytes: 0,
            max_bytes: DEFAULT_MAX_READ_BYTES,
        }
    }
}

/// A slice of a file, and enough about the whole to know what was left out.
#[derive(Debug, Clone)]
pub struct TextRead {
    pub text: String,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub total_bytes: u64,
    /// There is more after this slice. Not an error: reading the tail of a long
    /// log is the ordinary case, and refusing it would only make callers guess.
    pub truncated: bool,
}

/// The same, unread and unjudged.
#[derive(Debug, Clone)]
pub struct BytesRead {
    pub bytes: Vec<u8>,
    pub byte_offset: u64,
    pub total_bytes: u64,
    pub truncated: bool,
    /// Guessed conservatively from the extension, and never sniffed from
    /// content. Anything unrecognised is a byte stream.
    pub media_type: &'static str,
}

/// What a projection says about itself.
#[derive(Debug, Clone)]
pub struct RootInfo {
    pub root_path: String,
    pub name: String,
    pub exclude_count: usize,
    pub symlinks: SymlinkPolicy,
    pub max_read_bytes: u64,
}

impl FileRoot {
    /// Fix the root, or refuse to start.
    ///
    /// Canonicalized once, here, so that every later containment check compares
    /// against a path with no links and no `..` left in it.
    pub fn open(config: FileRootConfig) -> Result<Self> {
        for pattern in &config.exclude {
            validate_exclude_pattern(pattern)?;
        }
        let root = config.root.canonicalize()?;
        if !root.is_dir() {
            return Err(FilesError::NotADirectory);
        }
        Ok(Self {
            root,
            exclude: config.exclude,
            symlinks: config.symlinks,
            max_read_bytes: config.max_read_bytes.max(1),
        })
    }

    #[must_use]
    pub fn info(&self) -> RootInfo {
        RootInfo {
            root_path: self.root.display().to_string(),
            name: self
                .root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.root.display().to_string()),
            exclude_count: self.exclude.len(),
            symlinks: self.symlinks,
            max_read_bytes: self.max_read_bytes,
        }
    }

    #[must_use]
    pub fn max_read_bytes(&self) -> u64 {
        self.max_read_bytes
    }

    /// The canonical root, for whatever has to speak in absolute paths.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// The exclusion patterns, so that anything else producing paths applies
    /// the same ones. Not the caller's to widen: they are handed out to be
    /// obeyed, and there is no setter.
    #[must_use]
    pub fn exclude_patterns(&self) -> &[String] {
        &self.exclude
    }

    /// The real directory a path names, through the same confinement a read
    /// goes through.
    ///
    /// Exposed so that a watch cannot be registered on something a read would
    /// have refused — one resolution, one set of rules, rather than a second
    /// implementation that has to be kept in step with this one.
    pub fn resolve_directory(&self, path: &RelPath) -> Result<PathBuf> {
        let resolved = self.resolve(path)?;
        if !resolved.metadata.is_dir() {
            return Err(FilesError::NotADirectory);
        }
        Ok(resolved.real)
    }

    /// One directory, sorted and paged.
    ///
    /// The order is the name's byte order and nothing else. Directories are not
    /// hoisted above files here: that is a presentation choice, it belongs to
    /// whatever is drawing the list, and a paged listing needs an order that is
    /// total and stable more than it needs a pretty one.
    pub fn list(&self, path: &RelPath, page: &Page) -> Result<Listing> {
        let resolved = self.resolve(path)?;
        if !resolved.metadata.is_dir() {
            return Err(FilesError::NotADirectory);
        }
        let limit = page.limit.clamp(1, MAX_PAGE_LIMIT);
        let cursor = page
            .cursor
            .as_deref()
            .map(Self::decode_cursor)
            .transpose()?;

        // Sorted rather than taken in directory order: a directory read arrives
        // in whatever order the filesystem felt like, and the cursor is only
        // meaningful against a total order.
        //
        // Only one page of it is ever held. Reading the whole directory into a
        // map first — which this used to do — made the page limit a limit on
        // the answer and not on the work: one directory with a few million
        // entries in it is a few hundred megabytes of `DirEntry`, and the
        // caller who asked for ten names pays for all of them. Keeping the
        // smallest `limit + 1` names past the cursor bounds the memory to the
        // page, whatever is in the directory.
        let mut window: BTreeMap<Vec<u8>, fs::DirEntry> = BTreeMap::new();
        let mut beyond_window = false;
        for entry in fs::read_dir(&resolved.real)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = name_bytes(&file_name);
            if let Some(cursor) = &cursor
                && name.as_slice() <= cursor.as_slice()
            {
                continue;
            }
            // Exclusion is decided here rather than after the window is
            // chosen. An excluded entry that occupied a slot would let a
            // directory whose first page happens to be all excluded come back
            // empty, with no cursor and nothing to say the rest exists. It is
            // decided on names alone for everything but a link, which is the
            // one kind of entry whose real location has to be asked for.
            if let Some(text) = file_name.to_str()
                && self.excluded(&path.child(text))
            {
                continue;
            }
            if self.excluded_entry(&entry) {
                continue;
            }
            // One past the page, so the presence of a next page is known
            // without a second read.
            if window.len() == limit + 1 {
                let Some(largest) = window.keys().next_back() else {
                    break;
                };
                beyond_window = true;
                if name.as_slice() >= largest.as_slice() {
                    continue;
                }
                let largest = largest.clone();
                window.remove(&largest);
            }
            window.insert(name, entry);
        }

        let mut entries = Vec::new();
        let mut last_returned = None;
        let mut next_cursor = None;
        let windowed = window.len();
        for (name, entry) in window {
            if entries.len() == limit {
                next_cursor = last_returned.as_deref().map(Self::encode_cursor);
                break;
            }
            // Entries can disappear or become excluded between the scan
            // and description, so recheck before returning them.
            let Some(described) = self.describe(path, &entry.file_name(), &entry) else {
                continue;
            };
            last_returned = Some(name);
            entries.push(described);
        }
        // A short page that still has a directory behind it must hand back a
        // cursor, or the caller stops one entry early and calls it the end.
        if next_cursor.is_none()
            && (beyond_window || windowed > entries.len())
            && let Some(last) = &last_returned
        {
            next_cursor = Some(Self::encode_cursor(last));
        }
        Ok(Listing {
            path: path.as_str().to_owned(),
            entries,
            next_cursor,
        })
    }

    fn encode_cursor(name: &[u8]) -> String {
        let mut cursor = String::with_capacity(CURSOR_PREFIX.len() + name.len() * 2);
        cursor.push_str(CURSOR_PREFIX);
        for byte in name {
            use std::fmt::Write as _;
            // Writing to a String cannot fail. Avoiding `expect` here keeps
            // that invariant local without making it a process-ending path.
            let _ignored = write!(cursor, "{byte:02x}");
        }
        cursor
    }

    fn decode_cursor(cursor: &str) -> Result<Vec<u8>> {
        let Some(encoded) = cursor.strip_prefix(CURSOR_PREFIX) else {
            // Cursors emitted before the byte encoding were UTF-8 names.
            // Continue accepting them so an in-flight page can finish.
            return Ok(cursor.as_bytes().to_vec());
        };
        if encoded.len() % 2 != 0 {
            return Err(FilesError::InvalidCursor);
        }
        encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).map_err(|_| FilesError::InvalidCursor)?;
                u8::from_str_radix(text, 16).map_err(|_| FilesError::InvalidCursor)
            })
            .collect()
    }

    /// One entry, described the same way a listing would describe it.
    pub fn entry(&self, path: &RelPath) -> Result<Entry> {
        if path.is_root() {
            let resolved = self.resolve(path)?;
            return Ok(Entry {
                path: String::new(),
                name: self.info().name,
                kind: EntryKind::Directory,
                size_bytes: 0,
                modified_rfc3339: modified(&resolved.metadata),
                readable: true,
                unsupported: None,
                symlink_target: None,
            });
        }
        let resolved = self.resolve(path)?;
        let link = fs::symlink_metadata(self.root.join(path.as_str()))?;
        Ok(Entry {
            path: path.as_str().to_owned(),
            name: path.name().to_owned(),
            kind: kind_of(&resolved.metadata),
            size_bytes: resolved.metadata.len(),
            modified_rfc3339: modified(&resolved.metadata),
            readable: resolved.metadata.is_file() || resolved.metadata.is_dir(),
            unsupported: (!resolved.metadata.is_file() && !resolved.metadata.is_dir())
                .then_some(Unsupported::UnsupportedKind),
            symlink_target: link
                .file_type()
                .is_symlink()
                .then(|| link_target(&self.root.join(path.as_str())))
                .flatten(),
        })
    }

    /// A slice of a file, as text.
    ///
    /// Refuses anything with a NUL or an invalid encoding in the slice rather
    /// than handing back replacement characters: a caller that asked for text
    /// and got mojibake has been told the wrong thing about the file.
    /// When a truncated window ends partway through a UTF-8 character, its
    /// incomplete tail of at most three bytes is omitted. The returned length
    /// counts only the complete text; starting inside a character is refused.
    pub fn read_text(&self, path: &RelPath, window: &ByteWindow) -> Result<TextRead> {
        let read = self.read_bytes(path, window)?;
        if read.bytes.contains(&0) {
            return Err(FilesError::NotText);
        }
        let text = match String::from_utf8(read.bytes) {
            Ok(text) => text,
            Err(error) => {
                let utf8 = error.utf8_error();
                let tail_bytes = error.as_bytes().len() - utf8.valid_up_to();
                if !read.truncated || utf8.error_len().is_some() || tail_bytes > 3 {
                    return Err(FilesError::NotText);
                }
                let mut bytes = error.into_bytes();
                bytes.truncate(utf8.valid_up_to());
                String::from_utf8(bytes).map_err(|_| FilesError::NotText)?
            }
        };
        Ok(TextRead {
            byte_offset: read.byte_offset,
            byte_length: text.len() as u64,
            total_bytes: read.total_bytes,
            truncated: read.truncated,
            text,
        })
    }

    /// A slice of a file, as itself.
    pub fn read_bytes(&self, path: &RelPath, window: &ByteWindow) -> Result<BytesRead> {
        let resolved = self.resolve(path)?;
        if resolved.metadata.is_dir() {
            return Err(FilesError::IsADirectory);
        }
        if !resolved.metadata.is_file() {
            return Err(FilesError::NotFound);
        }
        let total_bytes = resolved.metadata.len();
        let wanted = window.max_bytes.clamp(1, self.max_read_bytes);

        let mut file = File::open(&resolved.real)?;
        // The gap between resolving a path and opening it is a gap somebody can
        // move a symlink into. This does not close it — that needs `openat`
        // walking the path a component at a time — but it does refuse the
        // switch after the fact, which turns a silent substitution into an
        // error. A directory listing has no equivalent check and neither does
        // Windows, so the README says what the root does and does not promise
        // instead of claiming the boundary is absolute.
        same_file(&file, &resolved.metadata)?;
        if window.offset_bytes > 0 {
            file.seek(SeekFrom::Start(window.offset_bytes))?;
        }
        let mut bytes = Vec::new();
        file.take(wanted).read_to_end(&mut bytes)?;
        let read = bytes.len() as u64;
        Ok(BytesRead {
            byte_offset: window.offset_bytes,
            truncated: window.offset_bytes.saturating_add(read) < total_bytes,
            total_bytes,
            media_type: media_type_of(path.name()),
            bytes,
        })
    }

    /// Whether a file's first pages look like text.
    ///
    /// A separate question from reading it, because a listing wants to say
    /// "openable" without pulling a gigabyte through memory to find out.
    pub fn looks_like_text(&self, path: &RelPath) -> Result<bool> {
        let read = self.read_bytes(
            path,
            &ByteWindow {
                offset_bytes: 0,
                max_bytes: SNIFF_BYTES as u64,
            },
        )?;
        Ok(!read.bytes.contains(&0) && std::str::from_utf8(&read.bytes).is_ok())
    }

    /// Describe one directory entry, or drop it.
    ///
    /// `None` means excluded — and nothing anywhere distinguishes that from a
    /// name the directory never had.
    fn describe(
        &self,
        parent: &RelPath,
        name: &std::ffi::OsStr,
        entry: &fs::DirEntry,
    ) -> Option<Entry> {
        // The name itself, not the ordering key: the two are the same bytes on
        // unix and deliberately are not on Windows, where the key is UTF-16
        // code units and only this is text.
        let Some(name) = name.to_str() else {
            // A name the platform cannot represent as text cannot be a path in
            // a JSON API, but the person is still owed the fact that something
            // is there.
            return Some(Entry {
                path: String::new(),
                name: name.to_string_lossy().into_owned(),
                kind: EntryKind::Other,
                size_bytes: 0,
                modified_rfc3339: None,
                readable: false,
                unsupported: Some(Unsupported::NonUtf8Name),
                symlink_target: None,
            });
        };
        let path = parent.child(name);
        if self.excluded(&path) {
            return None;
        }
        if self.excluded_entry(entry) {
            return None;
        }
        let link = entry.file_type().ok()?;
        let resolved = fs::metadata(entry.path());
        let inside = !link.is_symlink() || self.follows(&entry.path());
        let (kind, size_bytes, modified_at, readable, unsupported) = match (&resolved, inside) {
            (Ok(metadata), true) => {
                let usable = metadata.is_file() || metadata.is_dir();
                (
                    kind_of(metadata),
                    metadata.len(),
                    modified(metadata),
                    usable,
                    (!usable).then_some(Unsupported::UnsupportedKind),
                )
            }
            // A link out of the root, or a link to nothing. Named, not followed,
            // not opened.
            _ => (
                EntryKind::Symlink,
                0,
                None,
                false,
                Some(if link.is_symlink() {
                    Unsupported::OutsideRoot
                } else {
                    Unsupported::UnsupportedKind
                }),
            ),
        };
        Some(Entry {
            path: path.as_str().to_owned(),
            name: name.to_owned(),
            kind,
            size_bytes,
            modified_rfc3339: modified_at,
            readable,
            unsupported,
            symlink_target: link
                .is_symlink()
                .then(|| link_target(&entry.path()))
                .flatten(),
        })
    }

    /// Turn an accepted path into a real one, inside the root.
    fn resolve(&self, path: &RelPath) -> Result<Resolved> {
        if self.excluded(path) {
            return Err(FilesError::NotFound);
        }
        let joined = self.root.join(path.as_str());
        if self.symlinks == SymlinkPolicy::Never && self.traverses_a_link(path)? {
            return Err(FilesError::NotFound);
        }
        // Canonicalizing first is what makes one containment check enough: every
        // link and every `.` in the path is already gone by the time it is
        // compared, intermediate components included.
        let real = joined.canonicalize()?;
        if !self.contains(&real) {
            return Err(FilesError::NotFound);
        }
        if self.excluded_real(&real) {
            return Err(FilesError::NotFound);
        }
        let metadata = fs::metadata(&real)?;
        Ok(Resolved { real, metadata })
    }

    /// Whether a resolved path is under the root.
    ///
    /// `Path::starts_with` compares whole components, which is the entire point:
    /// `/srv/root-evil` starts with the *string* `/srv/root` and is not under
    /// the *path* `/srv/root`.
    fn contains(&self, candidate: &Path) -> bool {
        candidate.starts_with(&self.root)
    }

    /// Whether following this path would go through a link at all.
    ///
    /// Component by component, rather than inferred from comparing the resolved
    /// path with the requested one — on a system where `/tmp` is itself a link,
    /// that comparison says "yes" about every path there is.
    fn traverses_a_link(&self, path: &RelPath) -> Result<bool> {
        let mut walked = self.root.clone();
        for part in path.as_str().split('/').filter(|part| !part.is_empty()) {
            walked.push(part);
            if fs::symlink_metadata(&walked)?.file_type().is_symlink() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether following this link stays inside the root.
    fn follows(&self, link: &Path) -> bool {
        if self.symlinks == SymlinkPolicy::Never {
            return false;
        }
        link.canonicalize()
            .is_ok_and(|target| self.contains(&target))
    }

    /// Whether what a directory entry really is, is excluded.
    ///
    /// The entry came from reading its parent's real path, so for anything
    /// that is not a link its own path is already real and the answer needs no
    /// I/O. Only a link has to be resolved — and a link that will not resolve
    /// is judged by where it says it points, because the alternative is to
    /// list it with that text attached: `dangling -> secrets/missing` names
    /// the excluded directory to anyone who can list this one, and so does a
    /// link into a directory this process may not enter.
    fn excluded_entry(&self, entry: &fs::DirEntry) -> bool {
        let path = entry.path();
        // An entry whose type cannot be read is treated as a link: resolving
        // it is the question that cannot be answered wrongly.
        if entry.file_type().is_ok_and(|kind| !kind.is_symlink()) {
            return self.excluded_real(&path);
        }
        match path.canonicalize() {
            Ok(real) => self.excluded_real(&real),
            Err(_) => match fs::read_link(&path) {
                Ok(target) => self.excluded_real(&lexical_target(&path, &target)),
                // Neither resolvable nor readable as a link: there is nothing
                // left to decide it by, so it is not shown.
                Err(_) => true,
            },
        }
    }

    fn excluded_real(&self, real: &Path) -> bool {
        let Ok(relative) = real.strip_prefix(&self.root) else {
            return false;
        };
        let candidate = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        // The root itself is never excluded, the same way `excluded` answers
        // for the empty path: a bare `*` matches the empty name, and a root
        // that excluded itself would answer "not found" for its own listing.
        if candidate.is_empty() {
            return false;
        }
        self.exclude
            .iter()
            .any(|pattern| pattern_excludes(pattern, &candidate))
    }

    fn excluded(&self, path: &RelPath) -> bool {
        let candidate = path.as_str();
        if candidate.is_empty() {
            return false;
        }
        self.exclude
            .iter()
            .any(|pattern| pattern_excludes(pattern, candidate))
    }
}

struct Resolved {
    real: PathBuf,
    metadata: fs::Metadata,
}

fn kind_of(metadata: &fs::Metadata) -> EntryKind {
    if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

fn modified(metadata: &fs::Metadata) -> Option<String> {
    let modified = metadata.modified().ok()?;
    let stamp = chrono::DateTime::<chrono::Utc>::from(modified);
    Some(stamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Where a link's text points, worked out without touching the filesystem.
///
/// Only for a link that could not be resolved, where the text is all there is.
/// `..` is taken at its word rather than followed through whatever the
/// component before it really is, which is as close as text alone gets.
fn lexical_target(link: &Path, target: &Path) -> PathBuf {
    let mut resolved = link.parent().map(Path::to_path_buf).unwrap_or_default();
    for component in target.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                resolved = PathBuf::from(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::Normal(part) => resolved.push(part),
        }
    }
    resolved
}

fn link_target(link: &Path) -> Option<String> {
    fs::read_link(link)
        .ok()
        .map(|target| target.display().to_string())
}

#[cfg(unix)]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

/// The Windows ordering key: UTF-16 code units, big-endian, so the byte order
/// is the code-unit order.
///
/// Lossless on purpose. This used to be `to_string_lossy`, which folds every
/// unpaired surrogate to the same replacement character — two different names
/// then produce the same key, `BTreeMap::insert` keeps one of them, and the
/// other is gone from the listing with nothing said. A key is an identity, and
/// an identity that collides is not one. What a person reads comes from the
/// name itself, separately, so this never has to be text.
#[cfg(windows)]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().flat_map(u16::to_be_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

/// Refuse a file that stopped being the one that was resolved.
#[cfg(unix)]
fn same_file(file: &File, resolved: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let opened = file.metadata()?;
    if opened.dev() == resolved.dev() && opened.ino() == resolved.ino() {
        return Ok(());
    }
    Err(FilesError::NotFound)
}

#[cfg(not(unix))]
fn same_file(_file: &File, _resolved: &fs::Metadata) -> Result<()> {
    Ok(())
}

/// Conservative, extension-only, and never sniffed from the bytes.
///
/// Anything not on this list is a byte stream, which with `nosniff` and an
/// attachment disposition is a download rather than something a browser decides
/// to run.
fn media_type_of(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// Whether one pattern excludes one root-relative path.
///
/// Gitignore's shape, with one deliberate difference. There, `secrets/**` hides
/// what is in the directory and leaves the directory itself listed — which for
/// this crate would be the exact failure it refuses to ship: a person who wrote
/// that pattern to hide something would still be publishing the fact that
/// `secrets/` is there, and would believe otherwise. So a pattern ending in
/// `/**` excludes its own directory too, and a trailing `/` is read as naming
/// the directory rather than as a pattern that matches nothing.
fn pattern_excludes(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');
    // Anchored, because the pattern it came from was: `secrets/**` is about the
    // `secrets` at the root, and testing the bare name here would quietly widen
    // it to every directory of that name at every depth.
    if let Some(directory) = pattern.strip_suffix("/**")
        && glob_matches(directory, candidate)
    {
        return true;
    }
    if pattern.contains('/') {
        return glob_matches(pattern, candidate);
    }
    // A bare pattern is about a name, wherever in the tree that name turns up —
    // which is also what makes excluding a directory exclude everything under
    // it without a second pattern.
    candidate
        .split('/')
        .any(|segment| glob_matches(pattern, segment))
}

/// `*`, `?` and `**`, matched without backtracking.
///
/// Written here rather than taken as a dependency because the whole of it is
/// below, and because the one rule that matters — `*` stops at a path
/// separator, `**` does not — is the rule general glob crates make an option
/// and get wrong by default for this use.
/// Refuse a pattern whose meaning this matcher would get wrong.
///
/// The operators below are all of them: `*`, `?`, and `**`. Gitignore has
/// more — character classes, brace alternation, `\` escapes, a leading `!`
/// that re-includes — and every one of them, written here, would be matched as
/// a literal character. That failure is silent and it points the wrong way: the
/// person who wrote `[._]env` reads a clean listing as "hidden" when nothing
/// was hidden at all. So an unimplemented construct is an error at startup,
/// where it can still be fixed, and a filename that genuinely contains one of
/// these characters is reachable through `?`.
fn validate_exclude_pattern(pattern: &str) -> Result<()> {
    let reason = if pattern.is_empty() {
        Some("an empty pattern excludes nothing; remove it")
    } else if pattern.starts_with('!') {
        Some("gitignore's re-include is not implemented; remove the pattern instead")
    } else if pattern.contains('[') || pattern.contains(']') {
        Some("character classes are not implemented; use `?` for one character of any kind")
    } else if pattern.contains('{') || pattern.contains('}') {
        Some("brace alternation is not implemented; pass --exclude once per pattern")
    } else if pattern.contains('\\') {
        Some("backslash escapes are not implemented, and separators are always `/`")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(FilesError::InvalidExclude {
            pattern: pattern.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    fn matches(pattern: &[u8], candidate: &[u8]) -> bool {
        let mut pattern_index = 0;
        let mut candidate_index = 0;
        // Where to resume if a `*` turns out to have eaten too little.
        let mut star: Option<(usize, usize, bool)> = None;
        while candidate_index < candidate.len() {
            match pattern.get(pattern_index) {
                Some(b'*') => {
                    let crosses = pattern.get(pattern_index + 1) == Some(&b'*');
                    pattern_index += if crosses { 2 } else { 1 };
                    // A trailing `**` swallows the rest, separators included.
                    if crosses && pattern_index >= pattern.len() {
                        return true;
                    }
                    star = Some((pattern_index, candidate_index, crosses));
                }
                Some(b'?') if candidate[candidate_index] != b'/' => {
                    pattern_index += 1;
                    candidate_index += 1;
                }
                Some(&expected) if expected == candidate[candidate_index] => {
                    pattern_index += 1;
                    candidate_index += 1;
                }
                _ => match star {
                    Some((resume, consumed, crosses)) if crosses || candidate[consumed] != b'/' => {
                        pattern_index = resume;
                        candidate_index = consumed + 1;
                        star = Some((resume, consumed + 1, crosses));
                    }
                    _ => return false,
                },
            }
        }
        pattern[pattern_index..].iter().all(|byte| *byte == b'*')
    }
    matches(pattern.as_bytes(), candidate.as_bytes())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn excluded_targets_cannot_be_accessed_through_aliases() {
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("secrets")).unwrap();
        std::fs::write(base.path().join("secrets/key.pem"), "secret").unwrap();
        std::fs::write(base.path().join(".env"), "TOKEN=secret").unwrap();
        std::os::unix::fs::symlink("secrets", base.path().join("latest")).unwrap();
        std::os::unix::fs::symlink(".env", base.path().join("alias")).unwrap();
        let root = FileRoot::open(
            FileRootConfig::new(base.path())
                .with_exclude(["secrets/**".to_owned(), ".env".to_owned()]),
        )
        .unwrap();
        for path in ["latest", "latest/key.pem", "alias", ".ENV"] {
            assert!(
                matches!(
                    root.resolve(&RelPath::parse(path).unwrap()),
                    Err(FilesError::NotFound)
                ),
                "{path}"
            );
        }
        assert!(
            root.list(&RelPath::parse("").unwrap(), &Page::default())
                .unwrap()
                .entries
                .is_empty()
        );
    }

    use super::*;

    /// A root with something in it, and a neighbour that is not in it.
    fn projection() -> (tempfile::TempDir, FileRoot) {
        let base = tempfile::tempdir().expect("temporary base");
        let root = base.path().join("root");
        fs::create_dir_all(root.join("src")).expect("root");
        fs::create_dir_all(base.path().join("root-evil")).expect("the neighbour");
        fs::write(root.join("README.md"), "# hello\n").expect("a file");
        fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("a file");
        fs::write(base.path().join("root-evil/secret"), "not yours\n").expect("a file");
        fs::write(base.path().join("outside"), "not yours\n").expect("a file");
        let projection = FileRoot::open(FileRootConfig::new(&root)).expect("open the root");
        (base, projection)
    }

    fn path(raw: &str) -> RelPath {
        RelPath::parse(raw).expect("a path this projection accepts")
    }

    #[test]
    fn a_path_that_climbs_out_is_refused_before_the_filesystem_sees_it() {
        for raw in ["..", "../outside", "src/../../outside", "src/.."] {
            assert!(
                matches!(RelPath::parse(raw), Err(FilesError::InvalidPath(_))),
                "`{raw}` must be refused rather than resolved"
            );
        }
        // Absolute paths name something other than a place in this root.
        assert!(matches!(
            RelPath::parse("/etc/passwd"),
            Err(FilesError::InvalidPath(_))
        ));
        assert!(matches!(
            RelPath::parse("a\0b"),
            Err(FilesError::InvalidPath(_))
        ));
        // And one path has one spelling.
        assert_eq!(path("./src//main.rs").as_str(), "src/main.rs");
        assert_eq!(path("").as_str(), "");
    }

    // The three tests below build symlinks to prove the projection never
    // follows one out of its root. They are Unix-only because creating a
    // symlink on Windows needs a privilege the host may not grant, and a test
    // that passes or fails on the host's privileges reports on the host rather
    // than on this crate.
    //
    // What that leaves uncovered is real and worth naming: Windows reaches
    // outside a directory by its own means — junctions, `\\?\` paths, drive-
    // relative paths — and none of those are exercised here. The containment
    // logic itself is platform-independent and the rest of these tests run
    // everywhere, but a Windows-shaped escape needs Windows-shaped tests.
    #[cfg(unix)]
    #[test]
    fn a_sibling_whose_name_merely_starts_with_the_roots_is_not_inside_it() {
        let (base, projection) = projection();
        // The string check every version of this gets wrong first: `/…/root` is
        // a prefix of `/…/root-evil` as text, and not as a path.
        let escape = base.path().join("root-evil/secret");
        assert!(escape.exists(), "the neighbour is really there");
        assert!(!projection.contains(&escape));
        let link = base.path().join("root/to-neighbour");
        std::os::unix::fs::symlink(base.path().join("root-evil"), &link).expect("link");
        assert!(matches!(
            projection.read_text(&path("to-neighbour/secret"), &ByteWindow::default()),
            Err(FilesError::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_root_is_listed_and_never_followed() {
        let (base, projection) = projection();
        std::os::unix::fs::symlink(base.path().join("outside"), base.path().join("root/escape"))
            .expect("link");
        std::os::unix::fs::symlink("README.md", base.path().join("root/inside")).expect("link");

        let listing = projection
            .list(&RelPath::root(), &Page::default())
            .expect("list the root");
        let escape = listing
            .entries
            .iter()
            .find(|entry| entry.name == "escape")
            .expect("the link is listed rather than hidden");
        assert_eq!(escape.unsupported, Some(Unsupported::OutsideRoot));
        assert!(!escape.readable);
        assert!(escape.symlink_target.is_some());
        assert!(matches!(
            projection.read_text(&path("escape"), &ByteWindow::default()),
            Err(FilesError::NotFound)
        ));

        // A link that stays inside is an ordinary file, because a source tree
        // full of them has to stay browsable.
        let inside = projection
            .read_text(&path("inside"), &ByteWindow::default())
            .expect("a link inside the root is followed");
        assert_eq!(inside.text, "# hello\n");
    }

    /// The spellings that climb out on Windows and mean nothing on Unix.
    ///
    /// `RelPath::parse` walks `Path::components()`, which parses the way the
    /// host does — and that is what makes it safe here, in a way worth pinning
    /// because it is not obvious. On Windows `..\..` is two `ParentDir`
    /// components and `C:secret.txt` is a `Prefix`, so both are refused before
    /// anything touches the filesystem. On Unix each is one ordinary file name,
    /// harmless because that host will never read a backslash as a separator.
    ///
    /// The property is therefore that the platform which would *act* on these
    /// is the platform that rejects them. If parsing were ever replaced with
    /// something written by hand — splitting on `/` and checking for `..` — a
    /// Windows server would start honouring every one of these.
    #[cfg(windows)]
    #[test]
    fn the_windows_spellings_that_climb_out_are_refused_before_the_filesystem_sees_them() {
        for raw in [
            r"..\..",
            r"..\..\Windows\System32",
            r"src\..\..\outside",
            r"C:secret.txt",
            r"C:\Windows\System32\config\SAM",
            r"\\?\C:\Windows",
            r"\\server\share\secret",
        ] {
            assert!(
                matches!(RelPath::parse(raw), Err(FilesError::InvalidPath(_))),
                "`{raw}` must be refused rather than resolved"
            );
        }
    }

    /// Windows leaves a directory by means Unix does not have, and a junction is
    /// the one that matters most: unlike a symlink it needs no privilege, so
    /// anything able to write inside the root can create one. That is exactly
    /// the case the root is meant to bound, and it is the reason this test
    /// exists rather than the symlink tests simply being ported — those need a
    /// privilege the host may not grant, and this needs none.
    #[cfg(windows)]
    #[test]
    fn a_junction_out_of_the_root_is_listed_and_never_followed() {
        let base = tempfile::tempdir().expect("temporary base");
        let root = base.path().join("root");
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("README.md"), "# hello\n").expect("a file");
        let outside = base.path().join("outside");
        fs::create_dir_all(&outside).expect("the directory outside");
        fs::write(outside.join("secret.txt"), "not yours\n").expect("a file");

        // `mklink /J` rather than `symlink_dir`, because a junction is what an
        // unprivileged writer can actually make.
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(root.join("escape"))
            .arg(&outside)
            .output()
            .expect("mklink runs");
        assert!(
            made.status.success(),
            "creating a junction must not need a privilege: {}",
            String::from_utf8_lossy(&made.stderr)
        );

        let projection = FileRoot::open(FileRootConfig::new(&root)).expect("open the root");

        // The property the root promises: what is outside stays unreadable.
        assert!(
            matches!(
                projection.read_text(&path("escape/secret.txt"), &ByteWindow::default()),
                Err(FilesError::NotFound)
            ),
            "a junction out of the root must not be followed"
        );

        // And it is visible, because being able to see that something is there
        // without it being reachable is the same promise made for a symlink.
        let listing = projection
            .list(&RelPath::root(), &Page::default())
            .expect("list the root");
        let escape = listing
            .entries
            .iter()
            .find(|entry| entry.name == "escape")
            .expect("the junction is listed rather than hidden");
        assert!(
            !escape.readable,
            "a junction leaving the root must not be offered as readable"
        );
        assert_eq!(
            escape.unsupported,
            Some(Unsupported::OutsideRoot),
            "a junction leaving the root must be named as such, the way a symlink is"
        );
    }

    #[cfg(unix)]
    #[test]
    fn never_following_links_means_no_component_of_the_path_is_one() {
        let (base, _projection) = projection();
        std::os::unix::fs::symlink("src", base.path().join("root/link-to-src")).expect("link");
        let strict = FileRoot::open(
            FileRootConfig::new(base.path().join("root")).with_symlinks(SymlinkPolicy::Never),
        )
        .expect("open the root");
        assert!(matches!(
            strict.read_text(&path("link-to-src/main.rs"), &ByteWindow::default()),
            Err(FilesError::NotFound),
        ));
        assert!(
            strict
                .read_text(&path("src/main.rs"), &ByteWindow::default())
                .is_ok()
        );
    }

    #[test]
    fn an_excluded_entry_is_absent_rather_than_refused() {
        let (base, _projection) = projection();
        fs::write(base.path().join("root/.env"), "TOKEN=1\n").expect("a file");
        fs::create_dir_all(base.path().join("root/secrets")).expect("a directory");
        fs::write(base.path().join("root/secrets/key.pem"), "-----\n").expect("a file");
        fs::write(base.path().join("root/src/inner.pem"), "-----\n").expect("a file");
        let projection =
            FileRoot::open(FileRootConfig::new(base.path().join("root")).with_exclude([
                ".env".to_owned(),
                "secrets/**".to_owned(),
                "*.pem".to_owned(),
            ]))
            .expect("open the root");

        let listing = projection
            .list(&RelPath::root(), &Page::default())
            .expect("list the root");
        let names: Vec<&str> = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert!(!names.contains(&".env"), "{names:?}");
        assert!(
            !names.contains(&"secrets"),
            "being listed is disclosure, so an excluded directory is not listed: {names:?}"
        );
        assert!(names.contains(&"README.md"), "{names:?}");

        // And the refusal cannot be told apart from an absence, or it becomes an
        // oracle for what the exclusion is hiding.
        for excluded in [".env", "secrets/key.pem", "src/inner.pem"] {
            assert!(
                matches!(
                    projection.read_text(&path(excluded), &ByteWindow::default()),
                    Err(FilesError::NotFound)
                ),
                "`{excluded}` must answer exactly as a path that was never there"
            );
        }
    }

    #[test]
    fn a_directory_is_paged_in_one_stable_order() {
        let (base, _projection) = projection();
        for index in 0..10 {
            fs::write(base.path().join(format!("root/file-{index:02}")), "x").expect("a file");
        }
        let projection =
            FileRoot::open(FileRootConfig::new(base.path().join("root"))).expect("open the root");

        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = projection
                .list(
                    &RelPath::root(),
                    &Page {
                        limit: 4,
                        cursor: cursor.clone(),
                    },
                )
                .expect("a page");
            seen.extend(page.entries.iter().map(|entry| entry.name.clone()));
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let mut expected = vec!["README.md".to_owned(), "src".to_owned()];
        expected.extend((0..10).map(|index| format!("file-{index:02}")));
        expected.sort();
        assert_eq!(
            seen, expected,
            "paging must return every entry exactly once in byte order"
        );
        let mut unique = seen.clone();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "no entry is served twice: {seen:?}"
        );
    }

    #[test]
    fn a_page_whose_window_is_all_excluded_still_reaches_the_rest() {
        // The listing holds one page at a time rather than the whole
        // directory, so an excluded entry must be dropped during the scan. One
        // that occupied a window slot would make this first page empty, with no
        // cursor and nothing to say `visible` is there at all.
        let (base, _projection) = projection();
        let root = base.path().join("root");
        fs::remove_file(root.join("README.md")).expect("start from a known directory");
        fs::remove_dir_all(root.join("src")).expect("start from a known directory");
        for index in 0..20 {
            fs::write(root.join(format!("hidden-{index:02}.pem")), "x").expect("a file");
        }
        fs::write(root.join("visible.txt"), "x").expect("a file");
        let projection =
            FileRoot::open(FileRootConfig::new(&root).with_exclude(["*.pem".to_owned()]))
                .expect("open the root");

        let page = projection
            .list(
                &RelPath::root(),
                &Page {
                    limit: 2,
                    cursor: None,
                },
            )
            .expect("a page");

        let names: Vec<_> = page
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        assert_eq!(names, vec!["visible.txt".to_owned()]);
    }

    /// A link that cannot be resolved is judged by where it says it points.
    ///
    /// Listing it would publish its target text, which is the excluded name.
    #[cfg(unix)]
    #[test]
    fn a_dangling_link_into_an_excluded_directory_is_not_listed() {
        let (base, _projection) = projection();
        let root = base.path().join("root");
        fs::create_dir_all(root.join("sub")).expect("a directory");
        std::os::unix::fs::symlink("secrets/missing", root.join("dangling")).expect("link");
        std::os::unix::fs::symlink("../secrets/missing", root.join("sub/dangling")).expect("link");
        // Dangling too, and pointing nowhere excluded: still listed, so the
        // rule is about the target and not about links that fail to resolve.
        std::os::unix::fs::symlink("nowhere", root.join("lost")).expect("link");
        let projection =
            FileRoot::open(FileRootConfig::new(&root).with_exclude(["secrets/**".to_owned()]))
                .expect("open the root");

        let names = |directory: &str| -> Vec<String> {
            projection
                .list(&path(directory), &Page::default())
                .expect("a listing")
                .entries
                .into_iter()
                .map(|entry| entry.name)
                .collect()
        };
        assert_eq!(names(""), ["README.md", "lost", "src", "sub"]);
        assert_eq!(names("sub"), Vec::<String>::new());
    }

    /// `*` and `**` match the empty name, and the root's own real path is the
    /// empty name. The root still lists — as empty, because everything in it
    /// is excluded — rather than answering that it does not exist.
    #[test]
    fn a_pattern_that_matches_everything_does_not_exclude_the_root_itself() {
        let (base, _projection) = projection();
        for pattern in ["*", "**"] {
            let projection = FileRoot::open(
                FileRootConfig::new(base.path().join("root")).with_exclude([pattern.to_owned()]),
            )
            .expect("open the root");
            let listing = projection
                .list(&RelPath::root(), &Page::default())
                .expect("a pattern that matches everything must not hide the root");
            assert!(listing.entries.is_empty(), "`{pattern}`");
            assert_eq!(listing.next_cursor, None, "`{pattern}`");
            assert!(
                matches!(
                    projection.list(&path("src"), &Page::default()),
                    Err(FilesError::NotFound)
                ),
                "`{pattern}` still excludes everything under the root"
            );
        }
    }

    /// Excluded entries sort first here, and the page is smaller than what is
    /// left. The pages and their cursors must be exactly those of a directory
    /// the excluded entries were never in — which only holds if they are
    /// dropped before the page is chosen. Dropped afterwards, they fill the
    /// first window and it comes back empty with no cursor.
    #[test]
    fn excluded_entries_sorting_first_do_not_shift_pages_or_cursors() {
        let (base, _projection) = projection();
        let root = base.path().join("root");
        fs::remove_file(root.join("README.md")).expect("start from a known directory");
        fs::remove_dir_all(root.join("src")).expect("start from a known directory");
        for index in 0..6 {
            fs::write(root.join(format!("a-hidden-{index}.pem")), "x").expect("a file");
        }
        for name in ["v1", "v2", "v3"] {
            fs::write(root.join(name), "x").expect("a file");
        }
        let projection =
            FileRoot::open(FileRootConfig::new(&root).with_exclude(["*.pem".to_owned()]))
                .expect("open the root");
        assert_pages_are_v1_v2_then_v3(&projection);
    }

    /// The same promise for entries that are excluded only by what they really
    /// are: links whose own names match nothing.
    #[cfg(unix)]
    #[test]
    fn links_to_excluded_targets_sorting_first_do_not_shift_pages_or_cursors() {
        let (base, _projection) = projection();
        let root = base.path().join("root");
        fs::remove_file(root.join("README.md")).expect("start from a known directory");
        fs::remove_dir_all(root.join("src")).expect("start from a known directory");
        fs::create_dir(root.join("zz-secrets")).expect("a directory");
        for index in 0..6 {
            std::os::unix::fs::symlink("zz-secrets", root.join(format!("a-alias-{index}")))
                .expect("link");
        }
        for name in ["v1", "v2", "v3"] {
            fs::write(root.join(name), "x").expect("a file");
        }
        let projection =
            FileRoot::open(FileRootConfig::new(&root).with_exclude(["zz-secrets/**".to_owned()]))
                .expect("open the root");
        assert_pages_are_v1_v2_then_v3(&projection);
    }

    fn assert_pages_are_v1_v2_then_v3(projection: &FileRoot) {
        let page = |cursor: Option<&str>| {
            let listing = projection
                .list(
                    &RelPath::root(),
                    &Page {
                        limit: 2,
                        cursor: cursor.map(str::to_owned),
                    },
                )
                .expect("a page");
            let names: Vec<String> = listing
                .entries
                .into_iter()
                .map(|entry| entry.name)
                .collect();
            (names, listing.next_cursor)
        };
        // The cursor is the ordering key of `v2`, the last name returned:
        // its bytes on Unix, its UTF-16 code units on Windows.
        let after_v2 = FileRoot::encode_cursor(&name_bytes(std::ffi::OsStr::new("v2")));
        assert_eq!(
            page(None),
            (
                vec!["v1".to_owned(), "v2".to_owned()],
                Some(after_v2.clone())
            )
        );
        assert_eq!(page(Some(&after_v2)), (vec!["v3".to_owned()], None));
    }

    #[test]
    fn an_unsupported_exclude_pattern_is_refused_at_startup() {
        let (base, _projection) = projection();
        // Every one of these is gitignore syntax that this matcher would take
        // literally, hiding nothing while looking like it had.
        for pattern in ["[._]env", "*.{pem,key}", "!keep.pem", "secrets\\*", ""] {
            let error = FileRoot::open(
                FileRootConfig::new(base.path().join("root")).with_exclude([pattern.to_owned()]),
            )
            .err();
            assert!(
                matches!(error, Some(FilesError::InvalidExclude { .. })),
                "`{pattern}` must be refused rather than matched literally, got {error:?}"
            );
        }
        // The three operators that are implemented still open the root.
        assert!(
            FileRoot::open(FileRootConfig::new(base.path().join("root")).with_exclude([
                "*.pem".to_owned(),
                "secrets/**".to_owned(),
                "?.key".to_owned(),
            ]),)
            .is_ok()
        );
    }

    #[test]
    fn a_cursor_with_the_projection_prefix_must_be_well_formed() {
        let (_base, projection) = projection();
        let error = projection
            .list(
                &RelPath::root(),
                &Page {
                    limit: 1,
                    cursor: Some("name-bytes:not-hex".to_owned()),
                },
            )
            .expect_err("malformed cursor");
        assert!(matches!(error, FilesError::InvalidCursor));
    }

    #[test]
    fn a_long_file_is_truncated_and_says_so_rather_than_failing() {
        let (base, _projection) = projection();
        fs::write(base.path().join("root/log"), "0123456789").expect("a file");
        let projection =
            FileRoot::open(FileRootConfig::new(base.path().join("root")).with_max_read_bytes(4))
                .expect("open the root");
        let head = projection
            .read_text(&path("log"), &ByteWindow::default())
            .expect("the head of the file");
        assert_eq!(head.text, "0123");
        assert!(head.truncated);
        assert_eq!(head.total_bytes, 10);

        let tail = projection
            .read_text(
                &path("log"),
                &ByteWindow {
                    offset_bytes: 6,
                    max_bytes: 64,
                },
            )
            .expect("the tail of the file");
        assert_eq!(tail.text, "6789");
        assert!(!tail.truncated, "there is nothing after the tail");
        assert_eq!(tail.byte_offset, 6);
    }

    #[test]
    fn a_truncated_text_window_ends_at_a_complete_utf8_boundary() {
        let (base, projection) = projection();
        let file = base.path().join("root/unicode.txt");
        // Exercise the default preview cap with every incomplete prefix of a
        // two-, three-, or four-byte character.
        for character in ["é", "中", "😀"] {
            for partial_bytes in 1..character.len() {
                let prefix = "a".repeat(DEFAULT_MAX_READ_BYTES as usize - partial_bytes);
                let contents = format!("{prefix}{character}tail");
                fs::write(&file, &contents).expect("a long UTF-8 file");

                let text = projection
                    .read_text(&path("unicode.txt"), &ByteWindow::default())
                    .expect("a truncated preview with complete characters");
                assert_eq!(text.text, prefix);
                assert_eq!(text.byte_offset, 0);
                assert_eq!(text.byte_length, prefix.len() as u64);
                assert_eq!(text.total_bytes, contents.len() as u64);
                assert!(text.truncated);

                let bytes = projection
                    .read_bytes(&path("unicode.txt"), &ByteWindow::default())
                    .expect("the unchanged byte window");
                assert_eq!(
                    bytes.bytes,
                    contents.as_bytes()[..DEFAULT_MAX_READ_BYTES as usize]
                );
                assert_eq!(bytes.byte_offset, 0);
                assert_eq!(bytes.total_bytes, text.total_bytes);
                assert!(bytes.truncated);

                // The actual returned length is a valid offset from which to
                // read the omitted character again without losing its prefix.
                let next = projection
                    .read_text(
                        &path("unicode.txt"),
                        &ByteWindow {
                            offset_bytes: text.byte_length,
                            max_bytes: character.len() as u64,
                        },
                    )
                    .expect("the whole character at its aligned offset");
                assert_eq!(next.text, character);
                assert_eq!(next.byte_offset, prefix.len() as u64);
                assert_eq!(next.byte_length, character.len() as u64);
                assert!(next.truncated);
            }
        }
    }

    #[test]
    fn an_incomplete_utf8_tail_at_eof_and_invalid_text_still_fail() {
        let (base, projection) = projection();
        let file = base.path().join("root/not-text.txt");
        for character in ["é", "中", "😀"] {
            for partial_bytes in 1..character.len() {
                let mut contents = b"prefix: ".to_vec();
                contents.extend_from_slice(&character.as_bytes()[..partial_bytes]);
                fs::write(&file, &contents).expect("an incomplete UTF-8 sequence at EOF");
                let bytes = projection
                    .read_bytes(&path("not-text.txt"), &ByteWindow::default())
                    .expect("the complete byte file");
                assert!(!bytes.truncated);
                assert!(matches!(
                    projection.read_text(&path("not-text.txt"), &ByteWindow::default()),
                    Err(FilesError::NotText)
                ));
            }
        }

        for (name, contents, max_bytes) in [
            ("invalid", &b"ok\xfftail"[..], 3),
            ("nul", &b"ok\0tail"[..], 3),
            (
                "invalid before incomplete tail",
                &b"ok\xff\xf0\x9ftail"[..],
                5,
            ),
            ("overlong", &b"ok\xc0\x80tail"[..], 4),
            ("surrogate", &b"ok\xed\xa0\x80tail"[..], 5),
            ("bad continuation", &b"ok\xe2(tail"[..], 4),
        ] {
            fs::write(&file, contents).expect("invalid text followed by more bytes");
            let window = ByteWindow {
                offset_bytes: 0,
                max_bytes,
            };
            let bytes = projection
                .read_bytes(&path("not-text.txt"), &window)
                .expect("a truncated byte window");
            assert!(bytes.truncated, "{name}");
            assert!(
                matches!(
                    projection.read_text(&path("not-text.txt"), &window),
                    Err(FilesError::NotText)
                ),
                "{name} must not be accepted by trimming an incomplete tail"
            );
        }
    }

    #[test]
    fn a_text_window_starting_inside_a_utf8_character_is_refused() {
        let (base, projection) = projection();
        fs::write(base.path().join("root/unicode.txt"), "é中😀tail").expect("a UTF-8 file");
        let mut character_offset = 0;
        for character in ["é", "中", "😀"] {
            for skipped_bytes in 1..character.len() {
                let window = ByteWindow {
                    offset_bytes: (character_offset + skipped_bytes) as u64,
                    max_bytes: 4,
                };
                let bytes = projection
                    .read_bytes(&path("unicode.txt"), &window)
                    .expect("the non-aligned byte window remains readable");
                assert!(bytes.truncated);
                assert_eq!(bytes.byte_offset, window.offset_bytes);
                assert!(matches!(
                    projection.read_text(&path("unicode.txt"), &window),
                    Err(FilesError::NotText)
                ));
            }
            character_offset += character.len();
        }
    }

    #[test]
    fn a_binary_file_is_refused_as_text_and_served_as_bytes() {
        let (base, projection) = projection();
        fs::write(
            base.path().join("root/pixels.png"),
            [0x89, b'P', 0x00, 0x01],
        )
        .expect("a file");
        assert!(matches!(
            projection.read_text(&path("pixels.png"), &ByteWindow::default()),
            Err(FilesError::NotText)
        ));
        assert!(
            !projection
                .looks_like_text(&path("pixels.png"))
                .expect("sniff")
        );
        let bytes = projection
            .read_bytes(&path("pixels.png"), &ByteWindow::default())
            .expect("the bytes themselves");
        assert_eq!(bytes.bytes.len(), 4);
        assert_eq!(bytes.media_type, "image/png");
        // An extension nothing recognises is a byte stream, never a guess.
        fs::write(base.path().join("root/thing.weird"), [1, 2, 3]).expect("a file");
        assert_eq!(
            projection
                .read_bytes(&path("thing.weird"), &ByteWindow::default())
                .expect("bytes")
                .media_type,
            "application/octet-stream"
        );
    }

    #[test]
    fn a_directory_and_a_file_are_not_each_others_errors() {
        let (_base, projection) = projection();
        assert!(matches!(
            projection.read_text(&path("src"), &ByteWindow::default()),
            Err(FilesError::IsADirectory)
        ));
        assert!(matches!(
            projection.list(&path("README.md"), &Page::default()),
            Err(FilesError::NotADirectory)
        ));
        assert!(matches!(
            projection.list(&path("nope"), &Page::default()),
            Err(FilesError::NotFound)
        ));
    }

    #[test]
    fn a_glob_stops_at_a_separator_unless_it_is_a_double_star() {
        assert!(glob_matches("*.pem", "key.pem"));
        assert!(!glob_matches("*.pem", "secrets/key.pem"));
        assert!(glob_matches("secrets/**", "secrets/key.pem"));
        assert!(glob_matches("secrets/**", "secrets/deep/key.pem"));
        assert!(!glob_matches("secrets/*", "secrets/deep/key.pem"));
        assert!(glob_matches("**/target/**", "a/b/target/debug/x"));
        assert!(glob_matches("node_modules", "node_modules"));
        assert!(!glob_matches("node_modules", "node_modules_extra"));
        assert!(glob_matches("?.txt", "a.txt"));
        assert!(!glob_matches("?.txt", "ab.txt"));
        assert!(glob_matches("*", "anything"));
    }

    #[test]
    fn excluding_a_directorys_contents_excludes_the_directory() {
        // The gitignore behaviour this deliberately departs from: a person who
        // writes `secrets/**` to hide something must not be left publishing the
        // name of the thing they hid.
        assert!(pattern_excludes("secrets/**", "secrets"));
        assert!(pattern_excludes("secrets/**", "secrets/key.pem"));
        assert!(pattern_excludes("secrets/", "secrets"));
        assert!(pattern_excludes("secrets/", "secrets/key.pem"));
        assert!(pattern_excludes("a/b/**", "a/b"));
        assert!(!pattern_excludes("secrets/**", "secretsish"));
        assert!(!pattern_excludes("secrets/**", "a/secrets"));
        // A bare name still reaches everything under it.
        assert!(pattern_excludes("target", "a/target/debug/x"));
    }
}

#[cfg(feature = "api")]
pub mod api;
