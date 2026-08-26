//! Every action the page sends, answered through AFUI's real session runtime.
//!
//! What this exists to catch is not a broken read. It is a read that works
//! perfectly and comes back under a name the page does not accept, which is
//! invisible to every test that calls the Rust function directly and is the
//! whole of the experience for the person who clicked the file: a viewer that
//! opens and says the file could not be read.
//!
//! So the replies here are compared as JSON rather than deserialized into the
//! reply type. Deserializing would prove the two halves of one Rust enum agree
//! with each other; the page has no Rust enum, only a `type` string it asked
//! with and a `type` string it got back.

#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use agent_first_files::api::{ApiState, UI_KIND, UI_PROVIDER_ID, attach_runtime, run_runtime};
use agent_first_files::{FileRoot, FileRootConfig};
use agent_first_ui::test_support::RuntimeClient;
use agent_first_ui::{UiExpiry, UiSession, UiUrlDelivery};
use serde_json::{Value, json};
use tempfile::TempDir;

const TEXT: &str = "the file a person came to read\n";
/// A one-pixel PNG, so the image branch reads something a media type can be
/// taken from rather than a name with the right extension over nothing.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

fn workspace() -> TempDir {
    let workspace = tempfile::tempdir().expect("test workspace");
    std::fs::write(workspace.path().join("README.md"), TEXT).expect("write text file");
    std::fs::write(workspace.path().join("pixel.png"), PNG).expect("write image file");
    workspace
}

/// The state the window runs on, watcher included.
///
/// `watching` and not `new`, because `set_watch` is one of the actions under
/// test and the contract face — which starts no watcher — would refuse it for a
/// reason that has nothing to do with what this file is checking. A machine
/// where the platform watcher cannot start fails here rather than quietly
/// testing three actions instead of four.
fn state(workspace: &TempDir) -> ApiState {
    let root = FileRoot::open(FileRootConfig::new(workspace.path())).expect("open the root");
    ApiState::watching(root, "ui-runtime-has-no-bearer-0123456789".to_owned())
}

/// The page's contract in one line: an answer is an answer to the question it
/// was asked, and the page knows which question that was by its name.
fn assert_answers(action: &Value, reply: &Value) {
    let asked = action["type"].as_str().expect("the action names itself");
    assert_eq!(
        reply["type"].as_str(),
        Some(asked),
        "the page sends `{asked}` and refuses any reply not called `{asked}`, so this \
         one reaches a person as a viewer that could not read their file: {reply}"
    );
}

#[tokio::test]
async fn every_action_the_page_sends_is_answered_under_the_name_it_asked_with() {
    let workspace = workspace();
    let state = state(&workspace);
    let session = UiSession::<()>::new(UI_PROVIDER_ID, UI_KIND).expect("a files session");
    let (session, runtime) = attach_runtime(session, &state).expect("attach the files runtime");
    agent_first_files::api::publish_opening_state(&state, &runtime).expect("opening state");
    let served = tokio::spawn(run_runtime(state, runtime));
    let active = session
        .serve(axum::Router::new(), UiUrlDelivery::new(UiExpiry::Never))
        .await
        .expect("serve the files session");

    let mut page = RuntimeClient::connect(active.access_url(), "test-page")
        .await
        .expect("connect as the page");
    let _opening: Option<Value> = page.opening_state().await.expect("opening state");

    // Everything the page can ask for, in the order it asks: the tree, the
    // directories it is watching, a text file, an image.
    for action in [
        json!({"type": "browse", "path": ""}),
        json!({"type": "set_watch", "paths": [""]}),
        json!({"type": "read_text", "path": "README.md", "offset_bytes": 0}),
        json!({"type": "read_bytes", "path": "pixel.png", "offset_bytes": 0}),
    ] {
        let reply: Value = page
            .call(&action)
            .await
            .unwrap_or_else(|error| panic!("{} was refused outright: {error:?}", action["type"]));
        assert_answers(&action, &reply);
    }

    drop(page);
    served.abort();
}

#[tokio::test]
async fn opening_a_text_file_hands_the_page_the_bytes_and_not_only_a_shape() {
    let workspace = workspace();
    let state = state(&workspace);
    let session = UiSession::<()>::new(UI_PROVIDER_ID, UI_KIND).expect("a files session");
    let (session, runtime) = attach_runtime(session, &state).expect("attach the files runtime");
    agent_first_files::api::publish_opening_state(&state, &runtime).expect("opening state");
    let served = tokio::spawn(run_runtime(state, runtime));
    let active = session
        .serve(axum::Router::new(), UiUrlDelivery::new(UiExpiry::Never))
        .await
        .expect("serve the files session");

    let mut page = RuntimeClient::connect(active.access_url(), "test-page")
        .await
        .expect("connect as the page");
    let _opening: Option<Value> = page.opening_state().await.expect("opening state");
    let reply: Value = page
        .call(&json!({"type": "read_text", "path": "README.md", "offset_bytes": 0}))
        .await
        .expect("read a text file");

    assert_eq!(reply["file"]["total_bytes"], TEXT.len() as u64, "{reply}");
    assert_eq!(reply["file"]["truncated"], false, "{reply}");
    // The bytes never travel in the reply. AFUI holds them and hands the page
    // an opaque reference, so what has to be true here is that there is one.
    let blob = reply["blob"]["blob_url"]
        .as_str()
        .unwrap_or_else(|| panic!("a text read must hand over a body to fetch: {reply}"));
    let body = fetch_body(&format!("{}{blob}", active.access_url())).await;
    assert_eq!(body, TEXT);

    drop(page);
    served.abort();
}

/// One GET, without taking an HTTP client dependency for it.
async fn fetch_body(url: &str) -> String {
    let (authority, path) = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once('/'))
        .expect("an http access URL");
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .expect("connect to the session host");
    let request = format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
        .await
        .expect("send the blob request");
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
        .await
        .expect("read the blob response");
    let response = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .expect("a complete HTTP response");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    body.to_owned()
}
