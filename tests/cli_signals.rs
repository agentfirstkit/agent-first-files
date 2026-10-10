#![cfg(all(unix, feature = "api"))]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn ui_session_emits_terminal_result_for_interrupt_and_terminate() {
    stops_cleanly_when_signalled_at_the_ready_line(
        &["ui", "--mode", "session"],
        "ui_ready",
        |result| {
            assert_eq!(result["ending"], "interrupted", "{result}");
        },
    );
}

/// The same promise for the API server, whose ready line is the first thing a
/// supervisor reads: a signal sent the moment that line arrives must find the
/// handlers already installed.
#[test]
fn api_serve_emits_terminal_result_for_interrupt_and_terminate() {
    stops_cleanly_when_signalled_at_the_ready_line(
        &["api", "serve", "--port", "0"],
        "api_ready",
        |result| {
            assert!(
                result["api_url"]
                    .as_str()
                    .is_some_and(|url| url.starts_with("http://127.0.0.1:")),
                "{result}"
            );
        },
    );
}

fn stops_cleanly_when_signalled_at_the_ready_line(
    command: &[&str],
    ready_phase: &str,
    check_result: impl Fn(&serde_json::Value),
) {
    for signal in ["-INT", "-TERM"] {
        let root = tempfile::tempdir().unwrap();
        let mut child = Process(
            Command::new(env!("CARGO_BIN_EXE_affiles"))
                .args(command)
                .args(["--root", root.path().to_str().unwrap()])
                .env("AFUI_NO_REGISTRY", "1")
                .env(
                    "AFFILES_API_ACCESS_TOKEN_SECRET",
                    "affiles-signal-token-0123456789-abcdef",
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(event).is_err() {
                    return;
                }
            }
        });
        let ready = events.recv_timeout(Duration::from_secs(15)).unwrap();
        assert_eq!(ready["progress"]["phase"], ready_phase, "{ready}");
        assert!(
            Command::new("kill")
                .args([signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let result = events.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result["kind"], "result");
        assert_eq!(result["result"]["stopped"], true);
        check_result(&result["result"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "{command:?} did not stop after {signal}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success());
        reader.join().unwrap();
    }
}
