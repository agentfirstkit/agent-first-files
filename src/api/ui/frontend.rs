//! Defines affiles' document while [`agent_first_ui::UiPage`] owns resolution,
//! rendering, policy, and structural checks.

use agent_first_ui::{UiAppIcon, UiFrontend, UiPage};
use serde::Serialize;

pub const PROVIDER_ID: &str = "affiles";
pub const UI_KIND: &str = "files";
pub(super) const UI_API_VERSION: &str = "1";
const BUILTIN_APP_ICON: &str = include_str!("app-icon.svg");

#[derive(Clone, Copy, Serialize)]
struct ElementIds {
    root_name: &'static str,
    tree: &'static str,
    empty_state: &'static str,
    status: &'static str,
    viewer: &'static str,
    viewer_title: &'static str,
    viewer_meta: &'static str,
    viewer_body: &'static str,
    viewer_close: &'static str,
}

const ELEMENT_IDS: ElementIds = ElementIds {
    root_name: "root-name",
    tree: "tree",
    empty_state: "empty-state",
    status: "status",
    viewer: "viewer",
    viewer_title: "viewer-title",
    viewer_meta: "viewer-meta",
    viewer_body: "viewer-body",
    viewer_close: "viewer-close",
};

#[derive(Serialize)]
struct FilesDocument {
    ui_kind: &'static str,
    ui_api_version: &'static str,
    title: &'static str,
    brand: &'static str,
    heading: &'static str,
    elements: ElementIds,
    source_only_note: &'static str,
}

fn files_document() -> FilesDocument {
    FilesDocument {
        ui_kind: UI_KIND,
        ui_api_version: UI_API_VERSION,
        title: "Agent-First Files",
        brand: "Agent-First Files",
        heading: "Working directory",
        elements: ELEMENT_IDS,
        source_only_note: "Text files are shown as plain text. Images are displayed directly; other formats are not rendered.",
    }
}

pub struct FilesUi {
    pub(super) page: String,
    pub(super) stylesheet: Vec<u8>,
    app_icon: UiAppIcon,
    frontend: UiFrontend,
}

impl FilesUi {
    pub fn resolve(workspace_root: &std::path::Path) -> Result<Self, String> {
        // One conversion for every AFUI failure. The recovery action comes
        // from AFUI, which knows whether there is one — safe mode is the wrong
        // suggestion for a page affiles itself could not render, and AFUI is
        // the side that can tell those apart.
        let describe = |error: agent_first_ui::Error| match error.hint() {
            Some(hint) => format!("{error}; {hint}"),
            None => error.to_string(),
        };
        let frontend = UiFrontend::resolve(workspace_root, PROVIDER_ID, UI_KIND, UI_API_VERSION)
            .map_err(describe)?;
        let stylesheet = frontend
            .file("style.css")
            .map_err(describe)?
            .unwrap_or_else(|| include_bytes!("style.css").to_vec());
        let app_icon = frontend.app_icon(BUILTIN_APP_ICON).map_err(describe)?;
        let page = UiPage::builder(&frontend)
            .entry("templates/page.html.j2")
            .fallback(include_str!("page.html.j2"))
            .requires_element_map(&ELEMENT_IDS)
            .map_err(describe)?
            .runtime_marker("<!-- affiles:trusted-runtime -->")
            .runtime(Some("<script defer src=\"app.js\"></script>".to_owned()))
            .render(&files_document())
            .map_err(describe)?;
        Ok(Self {
            page,
            stylesheet,
            app_icon,
            frontend,
        })
    }

    #[must_use]
    pub fn frontend_id(&self) -> Option<&str> {
        self.frontend.frontend_id()
    }

    #[must_use]
    pub fn app_icon(&self) -> UiAppIcon {
        self.app_icon.clone()
    }

    pub(super) fn frontend(&self) -> &UiFrontend {
        &self.frontend
    }
}
