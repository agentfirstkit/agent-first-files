//! Bearer-protected loopback HTTP API and generated OpenAPI contract.

mod model;
mod schema;
mod server;
mod ui;

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub use schema::{openapi_document, schema_index, standalone_schemas};
pub use server::{ApiState, router};
pub use ui::{
    FilesUi, FilesUiRuntime, PROVIDER_ID as UI_PROVIDER_ID, UI_KIND, attach_runtime,
    publish_opening_state, run_runtime, ui_router, ui_security_policy,
};

/// Summary returned after exporting the generated API contract.
#[derive(Debug)]
pub struct ExportSummary {
    pub openapi_path: PathBuf,
    pub schema_index_path: PathBuf,
    pub schema_directory_path: PathBuf,
    pub schema_count: usize,
    pub file_count: usize,
}

/// Setup and export failures outside HTTP request handling.
#[derive(Debug)]
pub enum ApiSetupError {
    InvalidAccessToken(String),
    ContractExists(PathBuf),
    /// The contract path is a symbolic link. Writing through it would put a
    /// generated file somewhere this command was not pointed at.
    ContractIsALink(PathBuf),
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Serialize(serde_json::Error),
}

impl ApiSetupError {
    fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for ApiSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccessToken(message) => f.write_str(message),
            Self::ContractExists(path) => write!(
                f,
                "{} already exists; repeat with --force to replace it",
                path.display()
            ),
            Self::ContractIsALink(path) => write!(
                f,
                "{} is a symlink; --force replaces a generated file, it does not write through a link",
                path.display()
            ),
            Self::Io { operation, source } => write!(f, "{operation}: {source}"),
            Self::Serialize(source) => write!(f, "serialize OpenAPI contract: {source}"),
        }
    }
}

impl std::error::Error for ApiSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize(source) => Some(source),
            Self::InvalidAccessToken(_) | Self::ContractExists(_) | Self::ContractIsALink(_) => {
                None
            }
        }
    }
}

/// Resolve and validate the bearer credential without exposing it in output.
pub fn resolve_access_token(explicit: Option<&str>) -> Result<String, ApiSetupError> {
    let token = match explicit {
        Some(token) => token.to_string(),
        None => std::env::var("AFFILES_API_ACCESS_TOKEN_SECRET").map_err(|_| {
            ApiSetupError::InvalidAccessToken(
                "set AFFILES_API_ACCESS_TOKEN_SECRET or pass --access-token-secret".to_string(),
            )
        })?,
    };
    let bearer_safe = token.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
    });
    if !(32..=512).contains(&token.len()) || !bearer_safe {
        return Err(ApiSetupError::InvalidAccessToken(
            "the API access token must be 32-512 bearer-safe ASCII characters".to_string(),
        ));
    }
    Ok(token)
}

/// Export the generated contract: `directory/openapi.json`, the standalone
/// Schema index, and one file per Schema.
pub fn export_contract(directory: &Path, force: bool) -> Result<ExportSummary, ApiSetupError> {
    let openapi_path = directory.join("openapi.json");
    let schema_directory_path = directory.join("schemas");
    let schema_index_path = schema_directory_path.join("index.json");
    let schemas = standalone_schemas();

    fs::create_dir_all(&schema_directory_path)
        .map_err(|error| ApiSetupError::io("create OpenAPI export directory", error))?;
    if force {
        remove_stale_schema_files(&schema_directory_path, &schemas)?;
    }

    write_json(&openapi_path, &openapi_document(), force)?;
    write_json(&schema_index_path, &schema_index(), force)?;
    for (filename, schema) in &schemas {
        write_json(&schema_directory_path.join(filename), schema, force)?;
    }
    Ok(ExportSummary {
        openapi_path,
        schema_index_path,
        schema_directory_path,
        schema_count: schemas.len(),
        file_count: schemas.len() + 2,
    })
}

/// Write one contract file, whole or not at all, and never through a link.
///
/// `--force` used to mean `File::create`, which follows a symbolic link at the
/// target and truncates whatever is on the other end before a single byte of
/// the new contract is written. That makes an export command able to empty a
/// file somewhere else entirely, and it makes a failure partway through leave a
/// truncated public contract behind — a file that still parses as JSON right up
/// to where it stops. The bytes are rendered first, written to a private
/// temporary file beside the target, and put in place with one rename.
///
/// `--force` means "replace the generated file that is there". It is not
/// permission to write through a link, so a symlinked target is refused with it
/// as well as without it.
fn write_json(path: &Path, value: &serde_json::Value, force: bool) -> Result<(), ApiSetupError> {
    let mut rendered = serde_json::to_vec_pretty(value).map_err(ApiSetupError::Serialize)?;
    rendered.push(b'\n');

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ApiSetupError::ContractIsALink(path.to_path_buf()));
        }
        Ok(_) if !force => return Err(ApiSetupError::ContractExists(path.to_path_buf())),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ApiSetupError::io("inspect contract file", error)),
    }

    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("contract");
    let temp_path = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let install = (|| -> Result<(), ApiSetupError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| ApiSetupError::io("create contract file", error))?;
        file.write_all(&rendered)
            .map_err(|error| ApiSetupError::io("write contract file", error))?;
        file.sync_all()
            .map_err(|error| ApiSetupError::io("flush contract file", error))?;
        drop(file);
        // A rename replaces the target rather than reaching through it, so the
        // no-follow check above cannot be undone by what lands between them.
        fs::rename(&temp_path, path)
            .map_err(|error| ApiSetupError::io("install contract file", error))
    })();
    if install.is_err() {
        let _ignored = fs::remove_file(&temp_path);
    }
    install
}

/// A renamed or removed component would otherwise leave its old Schema file
/// behind, and a stale file in a committed contract reads as current.
fn remove_stale_schema_files(
    directory: &Path,
    schemas: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), ApiSetupError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| ApiSetupError::io("read schema export directory", error))?;
    for entry in entries {
        let entry = entry.map_err(|error| ApiSetupError::io("read schema export entry", error))?;
        let path = entry.path();
        let filename = entry.file_name().to_string_lossy().into_owned();
        if path.is_file() && filename.ends_with(".schema.json") && !schemas.contains_key(&filename)
        {
            fs::remove_file(&path)
                .map_err(|error| ApiSetupError::io("remove stale generated schema", error))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{export_contract, resolve_access_token};

    #[test]
    fn token_validation_rejects_short_or_unsafe_values() {
        assert!(resolve_access_token(Some("short")).is_err());
        assert!(resolve_access_token(Some(&"a".repeat(32))).is_ok());
        assert!(resolve_access_token(Some(&format!("{} ", "a".repeat(31)))).is_err());
    }

    #[test]
    fn export_requires_force_before_replacing_contract() {
        let temp = tempfile::tempdir().expect("create temp dir");
        export_contract(temp.path(), false).expect("first export");
        assert!(export_contract(temp.path(), false).is_err());
        export_contract(temp.path(), true).expect("forced export");
    }
}
