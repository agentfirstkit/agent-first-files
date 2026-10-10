use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use agent_first_data::skill::{
    self, SkillAction, SkillAgentSelection, SkillOptions, SkillScope, SkillSpec,
};
use agent_first_data::{
    ArgSpec, BoundOutcome, BuiltCliSpec, CliEmitter, CliSpec, CliSpecError, CliValue, Combination,
    CommandSpec, OutputFormat, OutputPlan, OutputSpec, OutputTo, ResolvedInvocation, SourceSet,
    build_afdata_cli, cli_error_event, cli_help_event, cli_parse_output, cli_version_event,
    json_error, json_progress, render_cli_reference,
};
use agent_first_files::api::{self, ApiState};
use agent_first_files::{DEFAULT_MAX_READ_BYTES, FileRoot, FileRootConfig, SymlinkPolicy};
use agent_first_ui::{UiDeliveryMode, UiSession};
use serde_json::json;

/// The skill this binary installs. A single file: it sends agents to
/// `affiles api --help` rather than shipping a reference tree to keep in step.
const SKILL_SPEC: SkillSpec = SkillSpec {
    name: "agent-first-files",
    source: include_str!("../skills/agent-first-files/SKILL.md"),
    title: "Agent-First Files",
    marker_slug: "affiles",
    assets: &[],
};

/// The named agents, and the fan-out value that is not one of them.
const AGENTS: [&str; 4] = ["codex", "claude-code", "opencode", "hermes"];
const EVERY_AGENT: &str = "all";

/// A server command keeps emitting events until it is stopped, so its data must
/// never land on the diagnostic stream.
fn stream_output() -> OutputSpec {
    OutputSpec::protocol_stream(
        ["json", "yaml", "plain"],
        ["stdout", "stderr"],
        "json",
        "stdout",
    )
}

fn finite_output() -> OutputSpec {
    OutputSpec::protocol_finite(
        ["json", "yaml", "plain"],
        ["split", "stdout", "stderr"],
        "json",
        "split",
    )
}

fn access_token_sources() -> SourceSet {
    SourceSet::config()
}

fn access_token_arg() -> ArgSpec {
    ArgSpec::option("--access-token-secret", "SOURCE")
        .about("Bearer credential; falls back to AFFILES_API_ACCESS_TOKEN_SECRET")
        .sources(access_token_sources())
}

/// The root, which is the security boundary and therefore has no default.
///
/// A convenient "current directory" becomes a home directory the first time
/// somebody runs this after `cd ~`, so it is required and the help says what
/// choosing it means.
fn root_arg() -> ArgSpec {
    ArgSpec::option("--root", "PATH").about(
        "The one directory to project. This is the security boundary: everything under it is \
         reachable by whoever holds the URL. Point it at a directory nobody else writes to — \
         containment is enforced by resolving each path, which a writer inside the root can \
         race",
    )
}

fn projection_args(command: CommandSpec) -> CommandSpec {
    command
        .arg(root_arg())
        .arg(ArgSpec::option("--exclude", "GLOB").repeatable().about(
            "Hide matches entirely, listings included. A pattern without `/` matches a \
                     name at any depth (`*.pem`); one with `/` matches the whole relative path \
                     (`secrets/**`), and excluding a directory's contents excludes the directory",
        ))
        .arg(
            ArgSpec::option_i64("--max-read-bytes", "BYTES")
                .default_i64(DEFAULT_MAX_READ_BYTES as i64)
                .about("Ceiling on one read, whatever a request asks for"),
        )
        .arg(ArgSpec::flag("--no-symlinks").about(
            "Follow no symlink at all. The default follows one whose target is inside the root \
             and refuses one whose target is not",
        ))
}

/// Where the interface appears, as one explicit mode rather than a negative
/// switch — the same shape `api serve --mode` already has.
///
/// `session` is for a person who is not at this machine, and it is not merely
/// tidier: a machine with no display cannot open a window at all, and a session
/// whose life is tied to a window nobody is looking at ends the moment somebody
/// closes it. In that mode the command itself is the bound, the way `api serve`
/// is — it runs until it is stopped.
///
/// No static default: a default here would read the same as a person having
/// typed `--mode window`, so `AFUI_DELIVERY` would never be reached and an
/// unattended run would always pop a window. [`resolve_delivery_mode`]
/// resolves the real default at run time: explicit `--mode` >
/// `AFUI_DELIVERY` > `window`.
///
fn ui_mode_arg() -> ArgSpec {
    UI_DELIVERY.arg("--mode")
}

/// Which deliveries this interface offers, declared once and used both to
/// build the flag above and to resolve the plan — so the words in `--help`
/// and the deliveries that work cannot drift apart.
const UI_DELIVERY: agent_first_ui::cli::UiDeliveryOffer =
    agent_first_ui::cli::UiDeliveryOffer::WithLink;

fn cli_spec() -> Result<BuiltCliSpec, CliSpecError> {
    let mut spec = CliSpec::new("affiles", env!("CARGO_PKG_VERSION"))
        .about("Project one directory tree, read-only, to a person who is not at this machine.")
        .display_name(env!("DISPLAY_NAME"))
        .lifecycle_output(finite_output())
        .command(CommandSpec::root())
        .command(
            CommandSpec::new(["api"])
                .about("Serve or export the OpenAPI 3.2 file projection contract."),
        )
        .command(
            projection_args(
                CommandSpec::new(["api", "serve"])
                    .about("Serve the bearer-protected projection API.")
                    .arg(
                        ArgSpec::option_i64("--port", "PORT")
                            .default_i64(9422)
                            .about("TCP port; use 0 to let the operating system choose"),
                    )
                    .arg(
                        ArgSpec::option_enum("--mode", ["local", "lan"])
                            .value_name("MODE")
                            .default("local")
                            .about(
                                "Network exposure: local binds 127.0.0.1; lan binds 0.0.0.0 and publishes the LAN address",
                            ),
                    )
                    .arg(access_token_arg()),
            )
            .combination(
                Combination::new("api-serve")
                    .action("api_serve")
                    .required(["root"])
                    .optional([
                        "port",
                        "mode",
                        "access_token_secret",
                        "exclude",
                        "max_read_bytes",
                        "no_symlinks",
                    ])
                    .output(stream_output()),
            ),
        )
        .command(
            CommandSpec::new(["api", "export"])
                .about("Write the generated OpenAPI document.")
                .arg(
                    ArgSpec::option("--directory", "PATH")
                        .default("openapi")
                        .about("Destination directory"),
                )
                .arg(ArgSpec::flag("--force").about("Replace an existing generated document"))
                .combination(
                    Combination::new("api-export")
                        .action("api_export")
                        .optional(["directory", "force"])
                        .output(finite_output()),
                ),
        )
        .command(
            projection_args(
                CommandSpec::new(["ui"])
                    .about("Open, directly link, or publish one directory tree."),
            )
            .arg(ui_mode_arg())
            .combination(
                Combination::new("ui")
                    .action("ui")
                    .required(["root"])
                    .optional([
                        "exclude",
                        "max_read_bytes",
                        "no_symlinks",
                        "mode",
                    ])
                    .output(stream_output()),
            ),
        )
        .command(
            CommandSpec::new(["skill"]).about("Manage the Agent-First Files agent skill."),
        )
        .command(skill_command(
            "status",
            "Report the installed skill state.",
            false,
        ))
        .command(skill_command("install", "Install the skill.", true))
        .command(skill_command("uninstall", "Remove the skill.", true));
    // Absent from a source tarball with no reachable .git, and the version
    // payload omits it rather than reporting the literal "unknown".
    if let Some(build) = Some(env!("GIT_SHA")).filter(|sha| *sha != "unknown") {
        spec = spec.build_id(build);
    }
    build_afdata_cli(spec)
}

fn main() -> ExitCode {
    let cli = match cli_spec() {
        Ok(cli) => cli,
        Err(error) => return emit_startup_error("cli_spec_invalid", &error.to_string()),
    };
    let app = match cli.bind_actions([
        (
            "api_serve",
            run_api_serve as fn(&ResolvedInvocation) -> ExitCode,
        ),
        ("api_export", run_api_export),
        ("ui", run_ui),
        ("skill_status", run_skill_status),
        ("skill_install", run_skill_install),
        ("skill_uninstall", run_skill_uninstall),
    ]) {
        Ok(app) => app,
        Err(error) => return emit_startup_error("cli_actions_invalid", &error.to_string()),
    };

    let outcome = match app.resolve_from(std::env::args_os()) {
        Ok(outcome) => outcome,
        Err(error) => {
            return emit_event(
                cli_error_event(&error),
                OutputFormat::Json,
                OutputTo::Stderr,
                error.exit_code(),
            );
        }
    };

    match outcome {
        BoundOutcome::Run(invocation) => invocation.run(),
        BoundOutcome::Docs(docs) => {
            write_text(&render_cli_reference(&cli), raw_stream(docs.output_plan()))
        }
        BoundOutcome::Help(help) => {
            let (format, output_to) = plan_output(help.output_plan());
            if format == OutputFormat::Plain {
                write_text(&help.plain(), raw_stream(help.output_plan()))
            } else {
                emit_event(cli_help_event(&help), format, output_to, 0)
            }
        }
        BoundOutcome::Version(version) => {
            let (format, output_to) = plan_output(version.output_plan());
            emit_event(cli_version_event(&version), format, output_to, 0)
        }
    }
}

fn plan_output(plan: &OutputPlan) -> (OutputFormat, OutputTo) {
    let format = plan
        .format()
        .and_then(|format| cli_parse_output(format).ok())
        .unwrap_or(OutputFormat::Json);
    let output_to = plan
        .destination()
        .and_then(|destination| OutputTo::parse(destination).ok())
        .unwrap_or(OutputTo::Split);
    (format, output_to)
}

fn raw_stream(plan: &OutputPlan) -> OutputTo {
    if plan.destination() == Some("stderr") {
        OutputTo::Stderr
    } else {
        OutputTo::Stdout
    }
}

/// One skill verb, in the two shapes that partition `--agent`.
fn skill_command(verb: &str, about: &str, force: bool) -> CommandSpec {
    let mut command = CommandSpec::new(["skill", verb])
        .about(about)
        .arg(
            ArgSpec::option_enum("--agent", std::iter::once(EVERY_AGENT).chain(AGENTS))
                .value_name("AGENT")
                .default(EVERY_AGENT)
                .about("Agent to manage"),
        )
        .arg(
            ArgSpec::option_enum("--scope", ["personal", "workspace"])
                .value_name("SCOPE")
                .default("personal")
                .about("Skill scope"),
        )
        .arg(ArgSpec::option("--skills-dir", "DIR").about("Directory that contains skill folders"));

    let mut every: Vec<&str> = vec!["scope"];
    let mut named: Vec<&str> = vec!["scope", "skills_dir"];
    if force {
        command =
            command.arg(ArgSpec::flag("--force").about(
                "Overwrite or remove an unmanaged Agent-First Files skill at the target path",
            ));
        every.push("force");
        named.push("force");
    }

    command
        .combination(
            Combination::new(format!("skill-{verb}-every-agent"))
                .action(format!("skill_{verb}"))
                .about("Target every agent that supports the scope")
                .fixed("agent", EVERY_AGENT)
                .optional(every)
                .output(finite_output()),
        )
        .combination(
            // `--skills-dir` names a single directory, so it is legal only once
            // the call has named one agent; the fan-out shape would have to
            // write one path for all of them.
            Combination::new(format!("skill-{verb}-one-agent"))
                .action(format!("skill_{verb}"))
                .about("Target one named agent; only this shape accepts --skills-dir")
                .fixed_one_of("agent", AGENTS)
                .optional(named)
                .output(finite_output()),
        )
}

fn run_skill_status(invocation: &ResolvedInvocation) -> ExitCode {
    run_skill(invocation, SkillAction::Status)
}

fn run_skill_install(invocation: &ResolvedInvocation) -> ExitCode {
    run_skill(invocation, SkillAction::Install)
}

fn run_skill_uninstall(invocation: &ResolvedInvocation) -> ExitCode {
    run_skill(invocation, SkillAction::Uninstall)
}

fn run_skill(invocation: &ResolvedInvocation, action: SkillAction) -> ExitCode {
    let (format, output_to) = plan_output(invocation.output_plan());
    let options = SkillOptions {
        agent: match optional_string(invocation, "agent").as_deref() {
            Some("codex") => SkillAgentSelection::Codex,
            Some("claude-code") => SkillAgentSelection::ClaudeCode,
            Some("opencode") => SkillAgentSelection::Opencode,
            Some("hermes") => SkillAgentSelection::Hermes,
            _ => SkillAgentSelection::All,
        },
        scope: match optional_string(invocation, "scope").as_deref() {
            Some("workspace") => SkillScope::Workspace,
            _ => SkillScope::Personal,
        },
        skills_dir: optional_string(invocation, "skills_dir"),
        force: invocation
            .optional("force")
            .and_then(CliValue::as_bool)
            .unwrap_or(false),
    };
    match skill::run_skill_admin(&SKILL_SPEC, action, &options) {
        Ok(report) => match serde_json::to_value(&report) {
            Ok(value) => emit_event(
                agent_first_data::json_result(value).build(),
                format,
                output_to,
                0,
            ),
            Err(error) => emit_domain_error(
                "serialization_failed",
                &format!("failed to serialize skill report: {error}"),
                format,
                output_to,
            ),
        },
        Err(err) => emit_domain_error("skill_error", &err.message, format, output_to),
    }
}

fn emit_domain_error(
    code: &str,
    message: &str,
    format: OutputFormat,
    output_to: OutputTo,
) -> ExitCode {
    match json_error(code, message).build() {
        Ok(event) => emit_event(event, format, output_to, 1),
        Err(_) => ExitCode::from(4),
    }
}

fn optional_string(invocation: &ResolvedInvocation, id: &str) -> Option<String> {
    invocation
        .optional(id)
        .and_then(CliValue::as_str)
        .map(str::to_string)
}

fn repeated_strings(invocation: &ResolvedInvocation, id: &str) -> Vec<String> {
    invocation
        .optional(id)
        .and_then(CliValue::as_list)
        .map(|values| {
            values
                .iter()
                .filter_map(CliValue::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn run_api_export(invocation: &ResolvedInvocation) -> ExitCode {
    let (format, output_to) = plan_output(invocation.output_plan());
    let directory = optional_string(invocation, "directory").unwrap_or_default();
    let force = invocation
        .optional("force")
        .and_then(CliValue::as_bool)
        .unwrap_or(false);
    let mut emitter = CliEmitter::from_output_to(output_to, format).with_strict_protocol();
    match api::export_contract(Path::new(&directory), force) {
        Ok(summary) => ExitCode::from(emitter.finish_result(json!({
            "openapi_path": summary.openapi_path.to_string_lossy().replace('\\', "/"),
            "schema_index_path": summary.schema_index_path.to_string_lossy().replace('\\', "/"),
            "schema_directory_path": summary
                .schema_directory_path
                .to_string_lossy()
                .replace('\\', "/"),
            "schema_count": summary.schema_count,
            "file_count": summary.file_count,
        }))),
        Err(error) => finish_error(&mut emitter, "openapi_export_failed", &error.to_string(), 1),
    }
}

/// `--mode`, parsed but not yet resolved against `AFUI_DELIVERY` — `None`
/// when the flag was not given. The registered enum only ever accepts AFUI's
/// three delivery words, so a parse failure here would be a defect in this
/// program's own registration, not a value a caller passed; it is still
/// propagated rather than assumed away.
fn delivery_mode_of(invocation: &ResolvedInvocation) -> Result<Option<UiDeliveryMode>, String> {
    agent_first_ui::cli::delivery_of(invocation, "mode").map_err(|error| error.to_string())
}

/// The delivery this call uses.
///
/// AFUI's priority — explicit `--mode` > `AFUI_DELIVERY` > `window` — is read
/// here because the readiness event has to name the resolved delivery too.
fn resolve_delivery_mode(explicit: Option<UiDeliveryMode>) -> Result<UiDeliveryMode, String> {
    UiDeliveryMode::resolve(explicit).map_err(|error| error.to_string())
}

/// Where the API listens, as one explicit choice rather than a pile of
/// overlapping switches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NetworkMode {
    Local,
    Lan,
}

impl NetworkMode {
    fn as_word(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Lan => "lan",
        }
    }

    fn bind_ip(self) -> Ipv4Addr {
        match self {
            Self::Local => Ipv4Addr::LOCALHOST,
            Self::Lan => Ipv4Addr::UNSPECIFIED,
        }
    }

    fn advertised_ip(self) -> Result<Ipv4Addr, ServeError> {
        match self {
            Self::Local => Ok(Ipv4Addr::LOCALHOST),
            // The same probe AFUI advertises a `link` session with, taken
            // from AFUI rather than copied: the reason it probes the multicast
            // route instead of the default one is a property of how VPN and
            // overlay interfaces behave, not of what affiles is publishing.
            Self::Lan => agent_first_ui::primary_lan_ipv4().map_err(|error| {
                ServeError::Runtime(format!(
                    "could not find this machine's LAN IPv4 address: {error}; connect to a \
                     trusted IPv4 network or use --mode local"
                ))
            }),
        }
    }

    fn ready_message(self) -> &'static str {
        match self {
            Self::Local => "The affiles API is available on this machine.",
            Self::Lan => {
                "The affiles API is on the trusted local network; keep the bearer credential private."
            }
        }
    }
}

/// Build the projection both verbs work from.
fn projection(invocation: &ResolvedInvocation) -> Result<FileRoot, String> {
    let root = optional_string(invocation, "root").unwrap_or_default();
    let max_read_bytes = invocation
        .optional("max_read_bytes")
        .and_then(CliValue::as_i64)
        .unwrap_or(DEFAULT_MAX_READ_BYTES as i64);
    if max_read_bytes < 1 {
        return Err("--max-read-bytes must be at least 1".to_string());
    }
    let symlinks = if invocation
        .optional("no_symlinks")
        .and_then(CliValue::as_bool)
        .unwrap_or(false)
    {
        SymlinkPolicy::Never
    } else {
        SymlinkPolicy::WithinRoot
    };
    FileRoot::open(
        FileRootConfig::new(&root)
            .with_exclude(repeated_strings(invocation, "exclude"))
            .with_symlinks(symlinks)
            .with_max_read_bytes(max_read_bytes as u64),
    )
    .map_err(|error| format!("--root {root}: {error}"))
}

fn run_api_serve(invocation: &ResolvedInvocation) -> ExitCode {
    let (format, output_to) = plan_output(invocation.output_plan());
    let port = match invocation.optional("port").and_then(CliValue::as_i64) {
        Some(value) if (0..=65535).contains(&value) => value as u16,
        Some(_) => return invalid_value("--port must be between 0 and 65535", format, output_to),
        None => 0,
    };
    let network = match optional_string(invocation, "mode").as_deref() {
        Some("lan") => NetworkMode::Lan,
        _ => NetworkMode::Local,
    };
    let mut emitter = CliEmitter::from_output_to(output_to, format).with_strict_protocol();
    let root = match projection(invocation) {
        Ok(root) => root,
        Err(message) => return finish_error(&mut emitter, "root_unusable", &message, 1),
    };
    let token = match access_token(invocation) {
        Ok(token) => token,
        Err(message) => return invalid_value(&message, format, output_to),
    };
    let token = match api::resolve_access_token(token.as_deref()) {
        Ok(token) => token,
        Err(error) => {
            return finish_error(
                &mut emitter,
                "api_access_token_invalid",
                &error.to_string(),
                1,
            );
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return finish_error(&mut emitter, "api_runtime_failed", &error.to_string(), 1);
        }
    };
    let started = Instant::now();
    let outcome = runtime.block_on(async {
        let advertised_ip = network.advertised_ip()?;
        let listener = tokio::net::TcpListener::bind((network.bind_ip(), port))
            .await
            .map_err(|error| ServeError::Runtime(format!("bind affiles API: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| ServeError::Runtime(format!("read API address: {error}")))?;
        let api_url = format!("http://{advertised_ip}:{}", address.port());
        let info = root.info();
        let shutdown = shutdown_signal();
        emitter
            .emit(
                json_progress(json!({
                    "phase": "api_ready",
                    "message": network.ready_message(),
                    "api_url": api_url,
                    "openapi_url": format!("{api_url}/openapi.json"),
                    "schema_index_url": format!("{api_url}/schemas/index.json"),
                    "mode": network.as_word(),
                    "port": address.port(),
                    "root_path": info.root_path,
                    "exclude_count": info.exclude_count,
                }))
                .trace(json!({"duration_ms": elapsed_ms(started)}))
                .build(),
            )
            .map_err(|_| ServeError::Output)?;
        axum::serve(listener, api::router(ApiState::new(root, token)))
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|error| ServeError::Runtime(format!("serve affiles API: {error}")))?;
        Ok::<String, ServeError>(api_url)
    });
    match outcome {
        Ok(api_url) => ExitCode::from(emitter.finish_result(json!({
            "api_url": api_url,
            "stopped": true,
        }))),
        Err(ServeError::Runtime(message)) => {
            finish_error(&mut emitter, "api_serve_failed", &message, 1)
        }
        Err(ServeError::Output) => ExitCode::from(4),
    }
}

/// Open a window onto the projection.
///
/// AFUI owns the listener, the credential, the browser process, its disposable
/// profile and the security headers; what affiles hands it is a router. The
/// bearer-protected contract is not on that listener at all, so the browser has
/// no route the API credential could travel on.
fn run_ui(invocation: &ResolvedInvocation) -> ExitCode {
    let (format, output_to) = plan_output(invocation.output_plan());
    let mut emitter = CliEmitter::from_output_to(output_to, format).with_strict_protocol();
    let mode = match delivery_mode_of(invocation).and_then(resolve_delivery_mode) {
        Ok(mode) => mode,
        Err(message) => return finish_error(&mut emitter, "ui_delivery_unavailable", &message, 1),
    };
    let root = match projection(invocation) {
        Ok(root) => root,
        Err(message) => return finish_error(&mut emitter, "root_unusable", &message, 1),
    };
    // Resolved, rendered and checked before a listener is bound, so a frontend
    // affiles cannot use costs a person an error rather than an empty window —
    // and never a quietly substituted built-in page.
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let files_ui = match api::FilesUi::resolve(&workspace_root) {
        Ok(files_ui) => Arc::new(files_ui),
        Err(message) => return finish_error(&mut emitter, "ui_frontend_unusable", &message, 1),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return finish_error(&mut emitter, "api_runtime_failed", &error.to_string(), 1);
        }
    };
    let started = Instant::now();
    let outcome = runtime.block_on(async {
        let info = root.info();
        // The window has no API of its own to authenticate against, so the
        // credential here is a placeholder the browser never sees and no route
        // ever checks. It exists because one state type serves both surfaces.
        //
        // `watching`, unlike `api serve`: a person looking at a directory is
        // the reader a change stream exists for, and the contract face has
        // none, so it does not start a platform watcher to feed nobody.
        let state =
            ApiState::watching(root, "window-delivery-has-no-bearer-0123456789".to_string());
        let session = UiSession::<()>::new(api::UI_PROVIDER_ID, api::UI_KIND)
            .map_err(|error| ServeError::Runtime(error.to_string()))?
            .with_subject(info.root_path.clone())
            .with_app_icon(files_ui.app_icon())
            .with_security_policy(api::ui_security_policy());
        let (session, ui_runtime) = api::attach_runtime(session, &state)
            .map_err(|error| ServeError::Runtime(error.to_string()))?;
        api::publish_opening_state(&state, &ui_runtime)
            .map_err(|error| ServeError::Runtime(error.to_string()))?;
        let ui_runtime_task = tokio::spawn(api::run_runtime(state, ui_runtime));
        let router = api::ui_router(Arc::clone(&files_ui));
        // Through the same value that declared `--mode`, not through the plan
        // constructor it happens to correspond to today. One value building
        // both is what stops the flag offering a word the plan would refuse,
        // or the plan honouring one the flag never listed.
        let plan = UI_DELIVERY
            .resolve(Some(mode))
            .map_err(|error| ServeError::Runtime(error.to_string()))?;
        let active = plan
            .start(session, router)
            .await
            .map_err(|error| ServeError::Runtime(error.to_string()))?;
        // What only affiles knows: what reaching this particular root through
        // this particular delivery costs. Where the UI actually is comes from
        // AFUI, so the two never disagree about which delivery ran.
        let caveat = match mode {
            // That `afui session serve` URL is a master key to every session
            // on this machine, not just this one — affiles is the only party
            // that knows what publishing adds to it, so affiles is the one
            // that has to say so.
            UiDeliveryMode::Session => {
                " That URL is a master key to every session on this machine, and this one adds \
                 the whole of this root to what it can show."
            }
            UiDeliveryMode::Link => {
                " The URL is a bearer capability: anyone holding it can browse the entire root. \
                 Share it only through a trusted channel and do not log or persist it."
            }
            UiDeliveryMode::Window => "",
        };
        // The one event whose job is to hand a `link` URL to the person who
        // asked for it, so AFUI reveals that one field by name. Everything
        // else — affiles' own fields included — goes through the ordinary
        // redacting emit below.
        let shutdown = shutdown_signal();
        emitter
            .emit(
                json_progress(agent_first_ui::cli::ready_event_revealing_link(
                    &active.facts(),
                    json!({
                        "phase": "ui_ready",
                        "message": format!(
                            "The directory is ready: {}.{caveat}",
                            mode.description()
                        ),
                        "root_path": info.root_path,
                        "exclude_count": info.exclude_count,
                        "ui_frontend_id": files_ui.frontend_id(),
                    }),
                ))
                .trace(json!({"duration_ms": elapsed_ms(started)}))
                .build(),
            )
            .map_err(|_| ServeError::Output)?;
        let ending = tokio::select! {
            outcome = active.wait() => outcome
                .map_err(|error| ServeError::Runtime(error.to_string()))?
                .ending(),
            () = shutdown => "interrupted",
        };
        let _runtime_stopped = ui_runtime_task.await;
        Ok(ending)
    });
    match outcome {
        Ok(ending) => ExitCode::from(emitter.finish_result(json!({
            "stopped": true,
            "ending": ending,
        }))),
        Err(ServeError::Runtime(message)) => finish_error(&mut emitter, "ui_failed", &message, 1),
        Err(ServeError::Output) => ExitCode::from(4),
    }
}

/// Read the credential the argument named. AFDATA already refused an
/// unacceptable source while resolving argv, so this only fails on a source
/// that cannot be read.
fn access_token(invocation: &ResolvedInvocation) -> Result<Option<String>, String> {
    let Some(raw) = optional_string(invocation, "access_token_secret") else {
        return Ok(None);
    };
    access_token_sources()
        .parse(&raw)
        .and_then(|source| source.read_secret())
        .map(|secret| Some(secret.expose_secret().to_string()))
        .map_err(|error| format!("--access-token-secret {error}"))
}

enum ServeError {
    Runtime(String),
    Output,
}

/// A future that completes when the process is asked to stop.
///
/// The handlers are installed by the call, not by the first poll of what it
/// returns. A supervisor reads the ready line and may signal at once; a handler
/// installed only when the serve loop first polls is not there yet, the signal
/// takes its default disposition, and the process dies without its terminal
/// event. So this is called before the ready event is written, and must be
/// called inside the runtime.
fn shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::interrupt()).ok(),
            signal(SignalKind::terminate()).ok(),
        )
    };
    async move {
        #[cfg(unix)]
        {
            // A signal whose handler could not be installed is one this
            // process cannot hear, not one that has arrived.
            let interrupted = async {
                match interrupt.as_mut() {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            let terminated = async {
                match terminate.as_mut() {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = interrupted => {},
                () = terminated => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _result = tokio::signal::ctrl_c().await;
        }
    }
}

fn invalid_value(message: &str, format: OutputFormat, output_to: OutputTo) -> ExitCode {
    let event = match json_error("cli_invalid_argument_value", message)
        .hint("run `affiles --help` and choose one registered combination")
        .build()
    {
        Ok(event) => event,
        Err(_) => return ExitCode::from(4),
    };
    emit_event(event, format, output_to, 2)
}

fn emit_event(
    event: agent_first_data::Event,
    format: OutputFormat,
    output_to: OutputTo,
    exit_code: u8,
) -> ExitCode {
    let mut emitter = CliEmitter::from_output_to(output_to, format).with_strict_protocol();
    match emitter.emit(event) {
        Ok(()) => ExitCode::from(exit_code),
        Err(_) => ExitCode::from(4),
    }
}

fn emit_startup_error(code: &str, message: &str) -> ExitCode {
    let event = match json_error(code, message).build() {
        Ok(event) => event,
        Err(_) => return ExitCode::from(4),
    };
    emit_event(event, OutputFormat::Json, OutputTo::Stderr, 1)
}

fn finish_error(
    emitter: &mut CliEmitter<Box<dyn Write>>,
    code: &str,
    message: &str,
    exit_code: u8,
) -> ExitCode {
    match emitter.emit_error(code, message) {
        Ok(()) => ExitCode::from(exit_code),
        Err(_) => ExitCode::from(4),
    }
}

fn write_text(text: &str, output_to: OutputTo) -> ExitCode {
    match agent_first_data::write_raw(text, output_to) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(4),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises every test in this module that touches
    /// `agent_first_ui::DELIVERY_ENV`: it is process-global state, and this
    /// binary's tests run in one process.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_env(value: &str) {
        // SAFETY: serialised by `ENV_LOCK`.
        unsafe { std::env::set_var(agent_first_ui::DELIVERY_ENV, value) };
    }

    fn clear_env() {
        // SAFETY: serialised by `ENV_LOCK`.
        unsafe { std::env::remove_var(agent_first_ui::DELIVERY_ENV) };
    }

    #[test]
    fn an_explicit_mode_wins_over_the_environment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        set_env("session");
        let resolved = resolve_delivery_mode(Some(UiDeliveryMode::Window));
        clear_env();
        assert_eq!(resolved.unwrap(), UiDeliveryMode::Window);
    }

    #[test]
    fn no_mode_and_no_environment_defaults_to_window() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        clear_env();
        assert_eq!(resolve_delivery_mode(None).unwrap(), UiDeliveryMode::Window);
    }

    #[test]
    fn no_mode_falls_back_to_the_environment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        set_env("session");
        let resolved = resolve_delivery_mode(None);
        clear_env();
        assert_eq!(resolved.unwrap(), UiDeliveryMode::Session);
    }

    #[test]
    fn an_unrecognised_environment_value_is_rejected_not_defaulted() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        set_env("lan");
        let resolved = resolve_delivery_mode(None);
        clear_env();
        let message = resolved.unwrap_err();
        assert!(message.contains("window"), "{message}");
        assert!(message.contains("link"), "{message}");
        assert!(message.contains("session"), "{message}");
    }

    #[test]
    fn link_is_available_from_either_source() {
        assert_eq!(
            resolve_delivery_mode(Some(UiDeliveryMode::Link)).unwrap(),
            UiDeliveryMode::Link
        );
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        set_env("link");
        let resolved = resolve_delivery_mode(None);
        clear_env();
        assert_eq!(resolved.unwrap(), UiDeliveryMode::Link);
    }
}
