//! The bearer-protected `/v1` surface, its fixed discovery face, and the one
//! serialization boundary every response goes through.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, extract::Path as AxumPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::model::{DirectoryResult, EntryResult, HealthResult, RootResult, TextFileResult};
use super::schema;
use crate::{ByteWindow, FileRoot, FilesError, MAX_PAGE_LIMIT, Page, RelPath};

const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct ApiState {
    pub(super) root: Arc<FileRoot>,
    access_token_secret: Arc<Vec<u8>>,
    changes: Option<Arc<Changes>>,
}

/// The live watch, and the fan-out that lets a page reconnect to it.
///
/// A broadcast rather than the watcher's own channel, because a page that
/// reloads wants the stream that is running rather than a second watcher — and
/// because the receiver can only be drained once.
pub(super) struct Changes {
    pub(super) watcher: crate::RootWatcher,
    pub(super) sender: tokio::sync::broadcast::Sender<Vec<String>>,
}

impl ApiState {
    #[must_use]
    pub fn new(root: FileRoot, access_token_secret: String) -> Self {
        Self {
            root: Arc::new(root),
            access_token_secret: Arc::new(access_token_secret.into_bytes()),
            changes: None,
        }
    }

    /// The same state, with a live watch behind it.
    ///
    /// Watching is deliberately not automatic. The contract surface has no
    /// event route and no reader asking for one, so `api serve` does not start
    /// a platform watcher it would only feed to nobody; the window does,
    /// because a person looking at a directory is exactly the reader.
    ///
    /// A watcher that cannot start is not an error. Browsing still works and
    /// the page says it is not live, which is worse than updating by itself and
    /// much better than refusing to open.
    #[must_use]
    pub fn watching(root: FileRoot, access_token_secret: String) -> Self {
        let mut state = Self::new(root, access_token_secret);
        let Ok((watcher, events)) = state.root.watch() else {
            return state;
        };
        let (sender, _first) = tokio::sync::broadcast::channel(256);
        let fan_out = sender.clone();
        // The core stream is a blocking std receiver, so it is drained on a
        // thread of its own rather than inside the runtime serving the page.
        std::thread::spawn(move || {
            while let Ok(crate::WatchEvent::Changed { paths }) = events.recv() {
                // An error here is "nobody is listening", which is the ordinary
                // state of a page nobody has open yet.
                let _ignored = fan_out.send(paths);
            }
        });
        state.changes = Some(Arc::new(Changes { watcher, sender }));
        state
    }

    pub(super) fn changes(&self) -> Option<&Changes> {
        self.changes.as_deref()
    }

    /// The projection both surfaces read.
    ///
    /// One root shared by the contract and the page, so the window can never
    /// reach something the API would refuse — the confinement is the root's,
    /// not each caller's to re-implement.
    #[must_use]
    pub fn root(&self) -> &FileRoot {
        &self.root
    }
}

struct ApiFailure {
    started: Instant,
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<&'static str>,
}

impl ApiFailure {
    fn new(
        started: Instant,
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            started,
            status,
            code,
            message: message.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        let mut builder = agent_first_data::json_error(self.code, &self.message)
            .retryable_if(false)
            .trace(trace(self.started));
        if let Some(hint) = self.hint {
            builder = builder.hint(hint);
        }
        let value: Value = match builder.build() {
            Ok(event) => event.into(),
            // The builder only rejects an empty code or message, both of which
            // are constants here; still, an error path may not panic.
            Err(_) => json!({
                "kind": "error",
                "error": {
                    "code": "api_error_envelope_failed",
                    "message": "the files API could not describe its own failure",
                    "retryable": false,
                },
                "trace": trace(self.started),
            }),
        };
        let mut response = json_response(self.status, value);
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"affiles\""),
            );
        }
        response
    }
}

fn trace(started: Instant) -> Value {
    json!({"duration_ms": started.elapsed().as_millis() as u64})
}

/// The one serialization boundary every contract response goes through.
///
/// Baseline §6: a domain response is an AFDATA result envelope, and the raw
/// HTTP serialization calls AFDATA redaction. Note what this does *not* touch —
/// file contents go out through [`file_bytes`], which is not a JSON domain
/// response and is not something to scrub. Redacting a person's own file would
/// corrupt the thing they came here to read.
fn result_response(started: Instant, payload: &impl Serialize) -> Response {
    let payload = match serde_json::to_value(payload) {
        Ok(payload) => payload,
        Err(error) => {
            return ApiFailure::new(
                started,
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_result_serialization_failed",
                error.to_string(),
            )
            .into_response();
        }
    };
    let event: Value = agent_first_data::json_result(payload)
        .trace(trace(started))
        .build()
        .into();
    json_response(StatusCode::OK, agent_first_data::redacted_value(&event))
}

/// A document that is its own contract, under its own media type.
fn document_response(value: Value, media_type: &'static str) -> Response {
    let mut response = Json(agent_first_data::redacted_value(&value)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(media_type));
    response
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

/// The contract surface, and only that.
///
/// The window is not mounted here. `affiles ui` binds a listener of its own
/// through AFUI, so the page and the bearer-protected contract never share a
/// port — a browser has no route it could reach the bearer through, rather than
/// a route it is merely not given the credential for.
pub fn router(state: ApiState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/openapi.json", get(openapi))
        .route("/schemas/index.json", get(schemas_index))
        .route("/schemas/{schema_file}", get(schema_file))
        .method_not_allowed_fallback(method_not_allowed);
    let protected = Router::new()
        .route("/v1/root", get(get_root))
        .route("/v1/directories", get(list_directory))
        .route("/v1/entries", get(get_entry))
        .route("/v1/files/text", get(read_text_file))
        .route("/v1/files/bytes", get(read_file_bytes))
        .method_not_allowed_fallback(method_not_allowed)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

    public
        .merge(protected)
        .fallback(not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(security_headers))
}

/// Process health and nothing else — no root path, no counts, no user data,
/// because this is the one route that answers without a credential.
async fn health() -> Response {
    result_response(
        Instant::now(),
        &HealthResult {
            service: "affiles",
            version: env!("CARGO_PKG_VERSION"),
            status: "ready",
        },
    )
}

async fn openapi() -> Response {
    document_response(schema::openapi_document(), "application/json")
}

async fn schemas_index() -> Response {
    document_response(schema::schema_index(), "application/json")
}

async fn schema_file(AxumPath(schema_file): AxumPath<String>) -> Response {
    match schema::standalone_schemas().get(&schema_file) {
        Some(schema) => document_response(schema.clone(), "application/schema+json"),
        None => ApiFailure::new(
            Instant::now(),
            StatusCode::NOT_FOUND,
            "schema_not_found",
            format!("no standalone schema named `{schema_file}`"),
        )
        .hint("list them at /schemas/index.json")
        .into_response(),
    }
}

/// A path is a query parameter, not a path segment.
///
/// A filesystem path is not a URL path, and spelling it as one produces exactly
/// the ambiguity this API must not have: whether `a%2Fb` is one segment or two,
/// what a name containing a percent or a newline does to routing, and where the
/// `/text` suffix ends and the file name begins.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PathQuery {
    #[serde(default)]
    path: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default)]
    path: String,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReadQuery {
    #[serde(default)]
    path: String,
    offset_bytes: Option<u64>,
    max_bytes: Option<u64>,
}

async fn get_root(State(state): State<ApiState>) -> Response {
    result_response(Instant::now(), &RootResult::from(state.root.info()))
}

async fn list_directory(State(state): State<ApiState>, query: Query<ListQuery>) -> Response {
    let started = Instant::now();
    let path = match RelPath::parse(&query.path) {
        Ok(path) => path,
        Err(error) => return files_error(started, error),
    };
    let page = Page {
        limit: query
            .limit
            .unwrap_or(crate::DEFAULT_PAGE_LIMIT)
            .min(MAX_PAGE_LIMIT),
        cursor: query.cursor.clone(),
    };
    match state.root.list(&path, &page) {
        Ok(listing) => result_response(started, &DirectoryResult::from(listing)),
        Err(error) => files_error(started, error),
    }
}

async fn get_entry(State(state): State<ApiState>, query: Query<PathQuery>) -> Response {
    let started = Instant::now();
    let path = match RelPath::parse(&query.path) {
        Ok(path) => path,
        Err(error) => return files_error(started, error),
    };
    match state.root.entry(&path) {
        Ok(entry) => result_response(started, &EntryResult::from(entry)),
        Err(error) => files_error(started, error),
    }
}

async fn read_text_file(State(state): State<ApiState>, query: Query<ReadQuery>) -> Response {
    let started = Instant::now();
    let path = match RelPath::parse(&query.path) {
        Ok(path) => path,
        Err(error) => return files_error(started, error),
    };
    let window = window_of(&state, &query);
    match state.root.read_text(&path, &window) {
        Ok(read) => result_response(started, &TextFileResult::new(query.path.clone(), read)),
        Err(error) => files_error(started, error),
    }
}

/// The one route that does not answer in an envelope.
///
/// A JPEG is not a JSON domain response and cannot be wrapped in one. It stays
/// inside the contract — OpenAPI 3.2 describes a binary response body perfectly
/// well — but it goes out as itself, with a conservative media type taken from
/// the extension, `nosniff`, and an attachment disposition, so nothing here
/// decides that a person's file is something a browser should run.
async fn read_file_bytes(State(state): State<ApiState>, query: Query<ReadQuery>) -> Response {
    let started = Instant::now();
    let path = match RelPath::parse(&query.path) {
        Ok(path) => path,
        Err(error) => return files_error(started, error),
    };
    let window = window_of(&state, &query);
    match state.root.read_bytes(&path, &window) {
        Ok(read) => {
            let mut response = (StatusCode::OK, read.bytes).into_response();
            let headers = response.headers_mut();
            if let Ok(media_type) = HeaderValue::from_str(read.media_type) {
                headers.insert(CONTENT_TYPE, media_type);
            }
            headers.insert(
                HeaderName::from_static("content-disposition"),
                HeaderValue::from_static("attachment"),
            );
            if let Ok(total) = HeaderValue::from_str(&read.total_bytes.to_string()) {
                headers.insert(HeaderName::from_static("x-total-bytes"), total);
            }
            response
        }
        Err(error) => files_error(started, error),
    }
}

fn window_of(state: &ApiState, query: &ReadQuery) -> ByteWindow {
    ByteWindow {
        offset_bytes: query.offset_bytes.unwrap_or(0),
        max_bytes: query
            .max_bytes
            .unwrap_or(state.root.max_read_bytes())
            .min(state.root.max_read_bytes()),
    }
}

/// Every core refusal, given its HTTP status and its stable code.
///
/// `NotFound` is what an excluded path and a path outside the root both arrive
/// here as, and nothing downstream can tell them apart from a path that was
/// never there. That is the point: a distinguishable refusal is an oracle.
/// One HTTP answer per domain error, with a message chosen here rather than
/// borrowed from the error's `Display`.
///
/// The two are not the same text on purpose. An `Io` error's `Display` is the
/// operating system's, and it carries absolute paths, device names and platform
/// wording — the projection's own job is to make the root's shape invisible,
/// and handing back "No such file or directory (os error 2) /home/…" undoes it
/// through the error channel. It also ties a stable error code to a string that
/// changes with the platform, which every caller matching on text then depends
/// on. The operator's copy keeps the detail; the response does not.
fn files_error(started: Instant, error: FilesError) -> Response {
    let (status, code, message, hint) = match &error {
        FilesError::NotFound => (
            StatusCode::NOT_FOUND,
            "entry_not_found",
            "no such entry under this root",
            None,
        ),
        FilesError::NotADirectory => (
            StatusCode::CONFLICT,
            "not_a_directory",
            "that path is not a directory",
            Some("read it with /v1/files/text or /v1/files/bytes"),
        ),
        FilesError::IsADirectory => (
            StatusCode::CONFLICT,
            "is_a_directory",
            "that path is a directory",
            Some("list it with /v1/directories"),
        ),
        FilesError::NotText => (
            StatusCode::CONFLICT,
            "not_text",
            "that file is not text",
            Some("read it with /v1/files/bytes"),
        ),
        // The reason is one of a fixed set this crate wrote, not a path.
        FilesError::InvalidPath(reason) => (StatusCode::BAD_REQUEST, "invalid_path", *reason, None),
        FilesError::InvalidCursor => (
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "invalid directory cursor",
            None,
        ),
        FilesError::PermissionDenied => (
            StatusCode::FORBIDDEN,
            "permission_denied",
            "this process may not read that entry",
            None,
        ),
        FilesError::TooManyWatches { .. } => (
            StatusCode::BAD_REQUEST,
            "too_many_watches",
            "more directories than this view may watch at once",
            Some("watch only the directories currently open"),
        ),
        FilesError::WatchRegistrationFailed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "watch_failed",
            "the directories shown by this view could not be watched",
            Some("nothing changed; retry, or re-read instead of waiting for events"),
        ),
        // Configuration this server accepted at startup cannot produce this
        // per request, but the mapping is exhaustive rather than a catch-all so
        // a new variant has to be answered here on purpose.
        FilesError::InvalidExclude { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "files_io_error",
            "this request could not be served",
            None,
        ),
        FilesError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "files_io_error",
            "this request could not be served",
            None,
        ),
    };
    // The operating system's own words are dropped here rather than routed
    // somewhere: this server has no per-request diagnostic channel, and the one
    // stream it could write to is the AFDATA event stream the CLI may have
    // pointed at stderr, where free text would corrupt the protocol. Giving the
    // operator the detail needs a sink built for it, which is recorded as
    // outstanding rather than improvised here.
    let _dropped_detail = &error;
    let mut failure = ApiFailure::new(started, status, code, message);
    if let Some(hint) = hint {
        failure = failure.hint(hint);
    }
    failure.into_response()
}

pub(super) fn api_error(
    started: Instant,
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    ApiFailure::new(started, status, code, message).into_response()
}

async fn require_bearer(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .map(HeaderValue::as_bytes)
        .and_then(|value| value.strip_prefix(b"Bearer "));
    let authorized =
        supplied.is_some_and(|value| constant_time_eq(value, state.access_token_secret.as_slice()));
    if !authorized {
        return api_error(
            Instant::now(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "a valid bearer credential is required",
        );
    }
    next.run(request).await
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn not_found() -> Response {
    api_error(
        Instant::now(),
        StatusCode::NOT_FOUND,
        "api_route_not_found",
        "API route not found",
    )
}

async fn method_not_allowed() -> Response {
    api_error(
        Instant::now(),
        StatusCode::METHOD_NOT_ALLOWED,
        "api_method_not_allowed",
        "HTTP method is not allowed for this route",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::AUTHORIZATION};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::{ApiState, router};
    use crate::{FileRoot, FileRootConfig};

    const TOKEN: &str = "test-token-0123456789-abcdefghijkl";

    fn app(root: &std::path::Path) -> (axum::Router, tempfile::TempDir) {
        let base = tempfile::tempdir().expect("temp");
        let projection = FileRoot::open(FileRootConfig::new(root)).expect("open the root");
        (router(ApiState::new(projection, TOKEN.to_string())), base)
    }

    fn workspace() -> tempfile::TempDir {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("src")).expect("dir");
        fs::write(base.path().join("README.md"), "# hello\n").expect("file");
        fs::write(base.path().join("src/main.rs"), "fn main() {}\n").expect("file");
        base
    }

    async fn call(app: &axum::Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn discovery_is_public_and_everything_about_the_root_is_not() {
        let workspace = workspace();
        let (app, _base) = app(workspace.path());
        for public in ["/health", "/openapi.json", "/schemas/index.json"] {
            let (status, _body) = call(&app, public, None).await;
            assert_eq!(status, StatusCode::OK, "{public}");
        }
        // The root path is a user value, so it is behind the credential rather
        // than in the health response every port scanner can read.
        let (status, body) = call(&app, "/v1/root", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "authentication_required");
        let (status, body) = call(&app, "/v1/root", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kind"], "result");
        assert_eq!(
            body["result"]["root_path"],
            workspace
                .path()
                .canonicalize()
                .expect("canonical root")
                .display()
                .to_string()
        );
    }

    #[tokio::test]
    async fn a_credential_in_the_query_string_is_not_a_credential() {
        let workspace = workspace();
        let (app, _base) = app(workspace.path());
        let (status, _body) = call(&app, &format!("/v1/root?token={TOKEN}"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn listing_and_reading_answer_in_the_envelope() {
        let workspace = workspace();
        let (app, _base) = app(workspace.path());
        let (status, body) = call(&app, "/v1/directories?path=", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["kind"], "result");
        let names: Vec<&str> = body["result"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter_map(|entry| entry["name"].as_str())
            .collect();
        assert_eq!(names, vec!["README.md", "src"]);

        let (status, body) = call(&app, "/v1/files/text?path=README.md", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["text"], "# hello\n");
        assert_eq!(body["result"]["truncated"], false);
    }

    #[tokio::test]
    async fn a_path_out_of_the_root_is_a_bad_request_and_a_missing_one_is_not_found() {
        let workspace = workspace();
        let (app, _base) = app(workspace.path());
        let (status, body) = call(&app, "/v1/files/text?path=../outside", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_path");

        let (status, body) = call(&app, "/v1/files/text?path=nope", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "entry_not_found");

        // A directory and a file are not each other's errors, and each says
        // which route to use instead.
        let (status, body) = call(&app, "/v1/files/text?path=src", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "is_a_directory");
        assert!(
            body["error"]["hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("/v1/directories"))
        );
    }

    #[tokio::test]
    async fn an_unknown_query_parameter_is_refused_rather_than_ignored() {
        let workspace = workspace();
        let (app, _base) = app(workspace.path());
        let (status, _body) = call(&app, "/v1/directories?path=&depth=9", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bytes_leave_as_themselves_and_never_as_something_to_run() {
        let workspace = workspace();
        fs::write(
            workspace.path().join("page.html"),
            "<script>alert(1)</script>",
        )
        .expect("file");
        let (app, _base) = app(workspace.path());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/files/bytes?path=page.html")
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        // Not text/html: an extension nothing on the conservative list
        // recognises is a byte stream, and it is delivered as an attachment
        // with nosniff so a browser never runs a person's workspace file.
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(
            response
                .headers()
                .get("content-disposition")
                .and_then(|value| value.to_str().ok()),
            Some("attachment")
        );
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
    }
}
