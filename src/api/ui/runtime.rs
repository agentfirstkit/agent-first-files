use agent_first_ui::{UiBlobRef, UiCall, UiCallError, UiSessionRuntime};
use serde::{Deserialize, Serialize};

use super::super::model::{DirectoryResult, EntryResult, RootResult};
use super::super::server::ApiState;
use crate::{ByteWindow, FilesError, Page, RelPath};

const TEXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

pub(super) const UI_BLOB_MEDIA_TYPES: [&str; 9] = [
    TEXT_MEDIA_TYPE,
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "image/x-icon",
    "application/octet-stream",
];

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum FilesUiAction {
    Browse {
        path: String,
        cursor: Option<String>,
    },
    SetWatch {
        paths: Vec<String>,
    },
    ReadText {
        path: String,
        #[serde(default)]
        offset_bytes: u64,
    },
    ReadBytes {
        path: String,
        #[serde(default)]
        offset_bytes: u64,
    },
}

/// One variant per action, under the action's own tag.
///
/// The page checks that a reply's `type` is the `type` it asked with, because
/// a reply arriving under some other name is a reply to some other question.
/// That check is only worth anything if these names are the action's names, so
/// the variants here are spelled exactly like [`FilesUiAction`]'s rather than
/// being named after what they carry — a `Text` answering a `read_text` reads
/// perfectly well in Rust and is rejected by every page that asks for it.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum FilesUiReply {
    Browse {
        root: RootResult,
        listing: DirectoryResult,
    },
    SetWatch,
    ReadText {
        entry: Option<EntryResult>,
        file: FilesUiText,
        blob: UiBlobRef,
    },
    ReadBytes {
        byte_offset: u64,
        total_bytes: u64,
        truncated: bool,
        blob: UiBlobRef,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct FilesUiText {
    path: String,
    byte_offset: u64,
    byte_length: u64,
    total_bytes: u64,
    truncated: bool,
}

/// Whether a page can expect the projection to replace its retained state
/// when something visible may have changed.
///
/// A live replacement names the directories affected by one watcher burst, so
/// work is bounded by the change rather than by everything a person expanded.
/// Opening state and lag recovery request a full resync; the page also does one
/// after reconnect because retained state may represent only the newest burst.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum FilesUiState {
    Watching {
        changed_paths: Vec<String>,
        resync_required: bool,
    },
    WatchUnavailable,
}

pub(super) type FilesRuntime = UiSessionRuntime<FilesUiAction, FilesUiReply, FilesUiState>;

pub(super) fn publish_opening_state(
    state: &ApiState,
    runtime: &FilesRuntime,
) -> agent_first_ui::Result<()> {
    runtime.publish_state(&state_of(state)).map(|_| ())
}

pub(super) async fn run(state: ApiState, runtime: FilesRuntime) {
    let mut changes = state.changes().map(|changes| changes.sender.subscribe());

    loop {
        tokio::select! {
            call = runtime.recv() => {
                let call = match call {
                    Ok(Some(call)) => call,
                    Ok(None) | Err(_) => return,
                };
                match execute_action(&state, &call) {
                    Ok(reply) => {
                        if call.finish(&reply).await.is_err() {
                            return;
                        }
                    }
                    Err(failure) => {
                        if call.fail(failure).await.is_err() {
                            return;
                        }
                    }
                }
            }
            change = receive_change(&mut changes), if changes.is_some() => {
                match change {
                    Ok(paths) => {
                        if runtime.publish_state(&FilesUiState::Watching {
                            changed_paths: paths,
                            resync_required: false,
                        }).is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        if runtime.publish_state(&FilesUiState::Watching {
                            changed_paths: Vec::new(),
                            resync_required: true,
                        }).is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        changes = None;
                        if runtime.publish_state(&FilesUiState::WatchUnavailable).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

async fn receive_change(
    changes: &mut Option<tokio::sync::broadcast::Receiver<Vec<String>>>,
) -> Result<Vec<String>, tokio::sync::broadcast::error::RecvError> {
    let Some(changes) = changes.as_mut() else {
        return Err(tokio::sync::broadcast::error::RecvError::Closed);
    };
    changes.recv().await
}

fn state_of(state: &ApiState) -> FilesUiState {
    if state.changes().is_some() {
        FilesUiState::Watching {
            changed_paths: Vec::new(),
            resync_required: true,
        }
    } else {
        FilesUiState::WatchUnavailable
    }
}

fn execute_action(
    state: &ApiState,
    call: &UiCall<FilesUiAction, FilesUiReply>,
) -> Result<FilesUiReply, UiCallError> {
    match call.action() {
        FilesUiAction::Browse { path, cursor } => browse(state, path, cursor.clone()),
        FilesUiAction::SetWatch { paths } => set_watch(state, paths),
        FilesUiAction::ReadText { path, offset_bytes } => {
            read_text(state, call, path, *offset_bytes)
        }
        FilesUiAction::ReadBytes { path, offset_bytes } => {
            read_bytes(state, call, path, *offset_bytes)
        }
    }
}

fn browse(
    state: &ApiState,
    path: &str,
    cursor: Option<String>,
) -> Result<FilesUiReply, UiCallError> {
    let path = RelPath::parse(path).map_err(files_call_error)?;
    let page = Page {
        limit: crate::DEFAULT_PAGE_LIMIT,
        cursor,
    };
    let listing = state.root().list(&path, &page).map_err(files_call_error)?;
    Ok(FilesUiReply::Browse {
        root: RootResult::from(state.root().info()),
        listing: DirectoryResult::from(listing),
    })
}

fn set_watch(state: &ApiState, paths: &[String]) -> Result<FilesUiReply, UiCallError> {
    let Some(changes) = state.changes() else {
        return Err(UiCallError::new(
            "watch_unavailable",
            "Filesystem change notification is unavailable for this view.",
        ));
    };
    // Parsed, not filtered. Dropping the paths that would not parse and then
    // reporting success left the page believing it was watching directories
    // this process had never registered.
    let paths: Vec<RelPath> = paths
        .iter()
        .map(|path| RelPath::parse(path))
        .collect::<Result<_, _>>()
        .map_err(files_call_error)?;
    changes
        .watcher
        .set_paths(state.root(), &paths)
        .map_err(files_call_error)?;
    Ok(FilesUiReply::SetWatch)
}

fn read_text(
    state: &ApiState,
    call: &UiCall<FilesUiAction, FilesUiReply>,
    path: &str,
    offset_bytes: u64,
) -> Result<FilesUiReply, UiCallError> {
    let relative = RelPath::parse(path).map_err(files_call_error)?;
    let window = ByteWindow {
        offset_bytes,
        max_bytes: state.root().max_read_bytes(),
    };
    let read = state
        .root()
        .read_text(&relative, &window)
        .map_err(files_call_error)?;
    let entry = state.root().entry(&relative).ok().map(EntryResult::from);
    let file = FilesUiText {
        path: path.to_owned(),
        byte_offset: read.byte_offset,
        byte_length: read.byte_length,
        total_bytes: read.total_bytes,
        truncated: read.truncated,
    };
    let blob = call
        .store_blob(TEXT_MEDIA_TYPE, read.text.into_bytes())
        .map_err(blob_call_error)?;
    Ok(FilesUiReply::ReadText { entry, file, blob })
}

fn read_bytes(
    state: &ApiState,
    call: &UiCall<FilesUiAction, FilesUiReply>,
    path: &str,
    offset_bytes: u64,
) -> Result<FilesUiReply, UiCallError> {
    let relative = RelPath::parse(path).map_err(files_call_error)?;
    let window = ByteWindow {
        offset_bytes,
        max_bytes: state.root().max_read_bytes(),
    };
    let read = state
        .root()
        .read_bytes(&relative, &window)
        .map_err(files_call_error)?;
    let blob = call
        .store_blob(read.media_type, read.bytes)
        .map_err(blob_call_error)?;
    Ok(FilesUiReply::ReadBytes {
        byte_offset: read.byte_offset,
        total_bytes: read.total_bytes,
        truncated: read.truncated,
        blob,
    })
}

fn files_call_error(error: FilesError) -> UiCallError {
    let (code, message, retryable) = match error {
        FilesError::NotFound => (
            "entry_not_found",
            "The requested entry was not found.",
            false,
        ),
        FilesError::NotADirectory => (
            "not_a_directory",
            "The requested entry is not a directory.",
            false,
        ),
        FilesError::IsADirectory => (
            "is_a_directory",
            "The requested entry is a directory.",
            false,
        ),
        FilesError::NotText => ("not_text", "The requested file is not text.", false),
        FilesError::InvalidPath(_) => (
            "invalid_path",
            "The path is not a valid root-relative path.",
            false,
        ),
        FilesError::InvalidCursor => ("invalid_cursor", "The directory cursor is invalid.", false),
        FilesError::PermissionDenied => (
            "permission_denied",
            "The requested entry cannot be read.",
            false,
        ),
        FilesError::TooManyWatches { .. } => (
            "too_many_watches",
            "This view asked to watch more directories than it may.",
            false,
        ),
        FilesError::WatchRegistrationFailed => (
            "watch_failed",
            "The directories shown by this view could not be watched.",
            true,
        ),
        // Configuration the window accepted at startup cannot fail per action,
        // but answering it here rather than with a catch-all means a new
        // variant has to be given a message on purpose.
        FilesError::InvalidExclude { .. } | FilesError::Io(_) => (
            "files_io_error",
            "The filesystem could not answer this UI action.",
            true,
        ),
    };
    UiCallError::new(code, message).retryable(retryable)
}

fn blob_call_error(_error: agent_first_ui::Error) -> UiCallError {
    UiCallError::new(
        "ui_blob_unavailable",
        "The requested file body could not be retained for this view.",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{FilesUiAction, FilesUiReply, browse, set_watch};
    use crate::api::ApiState;
    use crate::{FileRoot, FileRootConfig};

    const TOKEN: &str = "ui-test-token-0123456789-abcdefgh";

    fn state(root: &std::path::Path) -> ApiState {
        let projection = FileRoot::open(FileRootConfig::new(root)).expect("open the root");
        ApiState::new(projection, TOKEN.to_owned())
    }

    #[test]
    fn actions_are_typed_and_refuse_transport_or_unknown_fields() {
        let browse: FilesUiAction =
            serde_json::from_str(r#"{"type":"browse","path":"src","cursor":null}"#)
                .expect("typed browse action");
        assert!(matches!(browse, FilesUiAction::Browse { .. }));
        assert!(
            serde_json::from_str::<FilesUiAction>(
                r#"{"type":"browse","path":"src","cursor":null,"request_id":"mine"}"#,
            )
            .is_err(),
            "transport identity must not fit a Provider action"
        );
    }

    #[test]
    fn browsing_stops_at_exactly_one_directory() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("outer/inner")).expect("dirs");
        fs::write(base.path().join("outer/inner/deep.txt"), "deep\n").expect("file");
        let state = state(base.path());
        let FilesUiReply::Browse { listing, .. } = browse(&state, "", None).expect("browse") else {
            panic!("browse reply");
        };
        let encoded = serde_json::to_string(&listing).expect("listing");
        assert!(encoded.contains("outer"), "{encoded}");
        assert!(!encoded.contains("inner") && !encoded.contains("deep.txt"));
    }

    #[test]
    fn missing_and_excluded_directories_have_the_same_caller_safe_failure() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("secrets")).expect("dir");
        let projection = FileRoot::open(
            FileRootConfig::new(base.path()).with_exclude(["secrets/**".to_owned()]),
        )
        .expect("open the root");
        let state = ApiState::new(projection, TOKEN.to_owned());
        let excluded = browse(&state, "secrets", None).expect_err("excluded");
        let missing = browse(&state, "missing", None).expect_err("missing");
        assert_eq!(excluded.code(), "entry_not_found");
        assert_eq!(excluded.code(), missing.code());
        assert_eq!(excluded.message(), missing.message());
    }

    #[test]
    fn a_projection_without_a_watcher_says_so() {
        let base = tempfile::tempdir().expect("temp");
        let state = state(base.path());
        let error = set_watch(&state, &[String::new()]).expect_err("watch unavailable");
        assert_eq!(error.code(), "watch_unavailable");
    }
}
