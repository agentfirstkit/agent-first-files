//! The wire shapes, kept apart from the core types on purpose.
//!
//! The library returns typed Rust values with no serialization opinion; these
//! are what the contract promises. Two layers rather than one so that renaming
//! a field here is a contract change and renaming one there is not, and so the
//! core never grows a serde attribute deciding how somebody else's HTTP looks.

use serde::Serialize;

use crate::{Entry, Listing, RootInfo, TextRead};

#[derive(Debug, Serialize)]
pub struct RootResult {
    /// The absolute path this process is projecting. It is a user value, which
    /// is why it lives behind the bearer and not in `/health`.
    pub root_path: String,
    pub name: String,
    /// How many exclusion patterns are in force, not what they are: the
    /// patterns describe what is being kept back, and reading them out would
    /// undo some of that.
    pub exclude_count: usize,
    pub symlinks: &'static str,
    pub max_read_bytes: u64,
}

impl From<RootInfo> for RootResult {
    fn from(info: RootInfo) -> Self {
        Self {
            root_path: info.root_path,
            name: info.name,
            exclude_count: info.exclude_count,
            symlinks: match info.symlinks {
                crate::SymlinkPolicy::WithinRoot => "within_root",
                crate::SymlinkPolicy::Never => "never",
            },
            max_read_bytes: info.max_read_bytes,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EntryResult {
    pub path: String,
    pub name: String,
    pub kind: &'static str,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_rfc3339: Option<String>,
    pub readable: bool,
    /// Why this entry cannot be used the ordinary way, when it cannot. Present
    /// rather than implied, so a caller is never left to infer it from
    /// `readable: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

impl From<Entry> for EntryResult {
    fn from(entry: Entry) -> Self {
        Self {
            path: entry.path,
            name: entry.name,
            kind: entry.kind.as_word(),
            size_bytes: entry.size_bytes,
            modified_rfc3339: entry.modified_rfc3339,
            readable: entry.readable,
            unsupported: entry.unsupported.map(crate::Unsupported::as_word),
            symlink_target: entry.symlink_target,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DirectoryResult {
    pub path: String,
    pub entries: Vec<EntryResult>,
    pub entry_count: usize,
    /// Absent once the directory is exhausted, so "there is more" is a fact
    /// about this response rather than something to work out from a count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl From<Listing> for DirectoryResult {
    fn from(listing: Listing) -> Self {
        let entries: Vec<EntryResult> =
            listing.entries.into_iter().map(EntryResult::from).collect();
        Self {
            path: listing.path,
            entry_count: entries.len(),
            entries,
            next_cursor: listing.next_cursor,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TextFileResult {
    pub path: String,
    pub text: String,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub total_bytes: u64,
    /// There is more file after this slice. Not an error — reading the tail of
    /// a long log is the ordinary case.
    pub truncated: bool,
}

impl TextFileResult {
    pub fn new(path: String, read: TextRead) -> Self {
        Self {
            path,
            text: read.text,
            byte_offset: read.byte_offset,
            byte_length: read.byte_length,
            total_bytes: read.total_bytes,
            truncated: read.truncated,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResult {
    pub service: &'static str,
    pub version: &'static str,
    pub status: &'static str,
}
