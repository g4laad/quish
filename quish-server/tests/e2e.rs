//! End-to-end tests against the real auth + channel path, using `quishd`'s
//! root-free dev mode (`--dev-insecure-user`) and the real `quish` client
//! binary. No privilege drop, no PAM, no root — safe to run in CI.
//!
//! `#[ignore]`d by default: these spawn the `quish` client binary, which
//! `cargo test -p quish-server` does not build. Run
//! `cargo build --workspace && cargo test -p quish-server --test e2e -- --ignored`.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Unique-per-call temp dir, matching the style in `quish-auth/src/pubkey.rs`.
fn fresh_temp_dir(prefix: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Pull a `127.0.0.1:PORT` token out of a log line, tolerating a wrapper like
/// `addr=Some(127.0.0.1:49873)`.
fn extract_addr(line: &str) -> Option<SocketAddr> {
    for tok in line.split_whitespace() {
        if let Some(idx) = tok.find("127.0.0.1:") {
            let rest = &tok[idx..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.' && c != ':')
                .unwrap_or(rest.len());
            if let Ok(addr) = rest[..end].parse::<SocketAddr>() {
                return Some(addr);
            }
        }
    }
    None
}

/// Pull the hex fingerprint out of quishd's `... fingerprint=<hex>` startup log.
fn extract_fingerprint(line: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix("fingerprint=").map(str::to_string))
}

/// A running dev-mode `quishd`, killed on drop so no daemon leaks if a test
/// panics.
struct DevServer {
    child: Child,
    addr: SocketAddr,
    fingerprint: String,
}

impl DevServer {
    fn start(user: &str) -> DevServer {
        let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
        let home = fresh_temp_dir("quishd-home");

        // quishd's tracing writer defaults to stdout (unlike the client, which
        // sets stderr), so the readiness line arrives on stdout.
        let mut child = Command::new(&quishd)
            .args(["--listen", "127.0.0.1:0", "--dev-insecure-user", user])
            .env("HOME", &home)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn quishd");

        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut fingerprint: Option<String> = None;
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if let Some(fp) = extract_fingerprint(&line) {
                    fingerprint = Some(fp);
                }
                if line.contains("quishd listening")
                    && let Some(addr) = extract_addr(&line)
                {
                    let _ = tx.send((addr, fingerprint.clone()));
                }
                // Keep draining after the match (loop to EOF) so quishd's later
                // per-connection log lines can't fill the pipe and block it.
            }
        });

        let (addr, fingerprint) = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(ready) => ready,
            Err(_) => {
                // Don't leak the child: Drop hasn't taken ownership yet.
                let _ = child.kill();
                let _ = child.wait();
                panic!("quishd did not report a listen address within 10s");
            }
        };
        let fingerprint =
            fingerprint.expect("quishd logged a listen address but no certificate fingerprint");

        DevServer {
            child,
            addr,
            fingerprint,
        }
    }
}

impl Drop for DevServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run the real `quish` client binary against `server`. The `server` borrow ties
/// the lifetime (so callers can't run a client after the server is dropped) and
/// supplies the cert fingerprint we pre-trust below.
fn run_client(server: &DevServer, args: &[&str], password: Option<&str>) -> Output {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    if !quish.exists() {
        panic!(
            "quish client binary not found at {}; run `cargo build --workspace` first",
            quish.display()
        );
    }

    let home = fresh_temp_dir("quish-client-home");
    // Pre-trust the dev server's ephemeral cert: the client now prompts on the
    // controlling terminal for unknown host keys (StrictHostKeyChecking=ask), so
    // seed known_hosts to keep these non-interactive runs from blocking.
    let kh_dir = home.join(".config/quish");
    std::fs::create_dir_all(&kh_dir).unwrap();
    std::fs::write(
        kh_dir.join("known_hosts"),
        format!("{} {}\n", server.addr, server.fingerprint),
    )
    .unwrap();
    let mut cmd = Command::new(&quish);
    cmd.args(args).env("HOME", &home);
    if let Some(p) = password {
        cmd.env("QUISH_PASSWORD", p);
    }
    cmd.output().expect("spawn quish client")
}

#[test]
#[ignore]
fn exec_runs_command_and_returns_output() {
    let server = DevServer::start("testuser");
    let target = format!("testuser@{}", server.addr);

    let output = run_client(
        &server,
        &[&target, "echo", "quish-e2e-ok"],
        Some("anything"),
    );

    assert!(
        output.status.success(),
        "client did not exit successfully: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("quish-e2e-ok"),
        "unexpected stdout: {output:?}"
    );
}

#[test]
#[ignore]
fn exec_propagates_nonzero_exit_code() {
    let server = DevServer::start("testuser");
    let target = format!("testuser@{}", server.addr);

    let output = run_client(&server, &[&target, "exit", "7"], Some("anything"));

    assert_eq!(output.status.code(), Some(7), "output: {output:?}");
}

#[test]
#[ignore]
fn auth_rejects_unknown_user() {
    let server = DevServer::start("testuser");
    let target = format!("wronguser@{}", server.addr);

    let output = run_client(&server, &[&target, "echo", "nope"], Some("anything"));

    assert!(
        !output.status.success(),
        "client succeeded despite unknown user: {output:?}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("nope"),
        "command output leaked despite rejected auth: {output:?}"
    );
}
