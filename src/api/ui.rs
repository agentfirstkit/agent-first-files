//! The page a person browses and its AFUI session runtime.
//!
//! The page has no private HTTP or event protocol. It declares typed actions,
//! replies, and retained state; AFUI owns transport identity, reconnect,
//! latest-state delivery, bounds, and temporary byte bodies.

use std::sync::Arc;

use agent_first_ui::{UiBlobPolicy, UiPagePolicy, UiPageScript, UiSecurityPolicy};
use axum::Router;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::server::ApiState;

mod frontend;
mod runtime;

pub use frontend::{FilesUi, PROVIDER_ID, UI_KIND};

const UI_APP_JS: &str = include_str!("ui/app.js");

/// Opaque controller for this page's AFUI runtime.
pub struct FilesUiRuntime(runtime::FilesRuntime);

pub fn attach_runtime<T>(
    session: agent_first_ui::UiSession<T>,
    state: &ApiState,
) -> agent_first_ui::Result<(agent_first_ui::UiSession<T>, FilesUiRuntime)>
where
    T: Send + 'static,
{
    let policy = UiBlobPolicy::new(state.root().max_read_bytes(), runtime::UI_BLOB_MEDIA_TYPES);
    let (session, runtime) = session.with_runtime_and_blobs::<
        runtime::FilesUiAction,
        runtime::FilesUiReply,
        runtime::FilesUiState,
    >(policy)?;
    Ok((session, FilesUiRuntime(runtime)))
}

pub fn publish_opening_state(
    state: &ApiState,
    runtime: &FilesUiRuntime,
) -> agent_first_ui::Result<()> {
    runtime::publish_opening_state(state, &runtime.0)
}

pub async fn run_runtime(state: ApiState, runtime: FilesUiRuntime) {
    runtime::run(state, runtime.0).await;
}

/// The security posture this page is served under.
///
/// The page loads its own script, stylesheet, and AFUI-managed image bodies,
/// and connects only to the AFUI session runtime on the same origin.
#[must_use]
pub fn ui_security_policy() -> UiSecurityPolicy {
    UiPagePolicy::new(UiPageScript::SameOrigin)
        .allow_images()
        .allow_runtime()
        .into_security_policy()
}

/// Static page routes only. AFUI answers the reserved runtime and blob paths.
pub fn ui_router(ui: Arc<FilesUi>) -> Router {
    Router::new()
        .route("/app.js", get(app_js))
        .merge(agent_first_ui::page_routes(
            ui.page.clone(),
            ui.stylesheet.clone(),
            ui.frontend(),
        ))
}

/// affiles' trusted behaviour, appended after AFUI's browser kernel.
async fn app_js() -> Response {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        format!("{}\n{UI_APP_JS}", agent_first_ui::page_kernel_source()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::{FilesUi, UI_APP_JS, ui_router, ui_security_policy};

    async fn call(app: &axum::Router, uri: &str) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn app() -> axum::Router {
        ui_router(Arc::new(
            FilesUi::resolve(std::path::Path::new("/nonexistent")).expect("built-in page renders"),
        ))
    }

    #[tokio::test]
    async fn only_static_provider_routes_are_exposed() {
        let app = app();
        for asset in ["/", "/app.js", "/style.css"] {
            assert_eq!(call(&app, asset).await.0, StatusCode::OK, "{asset}");
        }
        for obsolete in ["/browse", "/watch", "/events", "/text", "/bytes"] {
            assert_eq!(
                call(&app, obsolete).await.0,
                StatusCode::NOT_FOUND,
                "{obsolete} must not remain a private UI protocol"
            );
        }
    }

    #[test]
    fn the_page_uses_the_complete_runtime_and_no_private_transport() {
        let _policy = ui_security_policy();
        assert!(UI_APP_JS.contains("afui.connect"));
        // An open file is a place, and AFUI owns what a place is in a browser:
        // the one history entry, both directions through it, Escape, and the
        // navigation control of a frame this page may be running inside. A
        // page that ran its own would be a page where those four disagree.
        assert!(UI_APP_JS.contains("afui.place("));
        for obsolete in [
            "afui.request",
            "afui.stream",
            "EventSource",
            "history.pushState",
            "history.back(",
            "addEventListener('popstate'",
            "event.key === 'Escape'",
            "'/browse'",
            "'/watch'",
            "'/events'",
            "'/text'",
            "'/bytes'",
        ] {
            assert!(!UI_APP_JS.contains(obsolete), "found `{obsolete}`");
        }
    }

    #[test]
    fn the_built_in_page_meets_every_frontend_rule() {
        let ui =
            FilesUi::resolve(std::path::Path::new("/nonexistent")).expect("built-in page renders");
        assert!(ui.frontend_id().is_none());
        assert!(!ui.page.contains("<!-- affiles:trusted-runtime -->"));
        assert!(ui.page.contains("<script defer src=\"app.js\"></script>"));
        assert!(!ui.stylesheet.is_empty());
        agent_first_ui::reject_frontend_script("page.html.j2", include_str!("ui/page.html.j2"))
            .expect("built-in template never hides a script");
    }

    #[test]
    fn the_runtime_never_assigns_workspace_content_as_markup() {
        let code = code_only(UI_APP_JS);
        for forbidden in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
        ] {
            assert!(!code.contains(forbidden), "app.js uses `{forbidden}`");
        }
        assert!(code.contains("textContent"));
        assert!(UI_APP_JS.contains("new Intl.DateTimeFormat"));
    }

    fn code_only(source: &str) -> String {
        let mut code = String::with_capacity(source.len());
        let mut in_block = false;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if in_block {
                if let Some(rest) = trimmed.split_once("*/") {
                    in_block = false;
                    code.push_str(rest.1);
                    code.push('\n');
                }
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some((before, rest)) = trimmed.split_once("/*") {
                code.push_str(before);
                code.push('\n');
                if !rest.contains("*/") {
                    in_block = true;
                }
                continue;
            }
            code.push_str(line);
            code.push('\n');
        }
        code
    }
}
