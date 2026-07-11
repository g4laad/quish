//! End-to-end tests against the REAL privilege-separated path: a root monitor
//! that binds + re-execs a chrooted, setuid `quish` worker, authenticates with
//! PAM (`/etc/pam.d/quish`), and spawns per-channel session helpers that setuid
//! to the authenticated login user and exec their shell.
//!
//! Unlike `e2e.rs` (dev mode: single process, no PAM, no privdrop), these MUST
//! run as root in a Linux userland with libpam, a `quish` PAM policy, a `quish`
//! worker account, and a login user with a password. That environment is the
//! podman image built from `dist/test/Containerfile`; run the whole thing with
//! `dist/test/run-privsep-e2e.sh`.
//!
//! `#[ignore]`d by default: they spawn the `quish` client binary (which
//! `cargo test -p quish-server` does not build) and require root + PAM. The
//! image CMD runs them with `--ignored`.

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

/// The login user + password provisioned in the container (see Containerfile).
fn test_user() -> String {
    std::env::var("QUISH_TEST_USER").expect("QUISH_TEST_USER must be set (see Containerfile)")
}
fn test_password() -> String {
    std::env::var("QUISH_TEST_PASSWORD")
        .expect("QUISH_TEST_PASSWORD must be set (see Containerfile)")
}

/// A running privsep `quishd` (root monitor + chrooted worker), killed on drop
/// so no daemon leaks if a test panics.
struct PrivsepServer {
    child: Child,
    addr: SocketAddr,
    fingerprint: String,
}

impl PrivsepServer {
    fn start() -> PrivsepServer {
        // Guardrail: privsep mode forks/chroots/setuids and requires root. The
        // real gate is `#[ignore]` + the container CMD; this just fails clearly
        // if someone runs the file directly on a non-root host.
        assert!(
            nix::unistd::geteuid().is_root(),
            "privsep_e2e tests must run as root inside the privsep container \
             (see dist/test/run-privsep-e2e.sh)"
        );

        let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));

        // Privsep mode: no --dev-insecure-user. The monitor binds and re-execs
        // the worker, which logs the resolved listen address on inherited
        // stdout (transport.rs), exactly like dev mode.
        let mut child = Command::new(&quishd)
            .args([
                "--listen",
                "127.0.0.1:0",
                "--privsep-dir",
                "/run/quishd",
                "--privsep-user",
                "quish",
            ])
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

        PrivsepServer {
            child,
            addr,
            fingerprint,
        }
    }

    /// Seed a fresh client `$HOME` with `known_hosts` pre-trusting this server's
    /// ephemeral cert, returning the home dir. Callers that drive the client
    /// directly (PTY scenarios) reuse this instead of `run_client`.
    fn client_home(&self) -> PathBuf {
        let home = fresh_temp_dir("quish-client-home");
        let kh_dir = home.join(".config/quish");
        std::fs::create_dir_all(&kh_dir).unwrap();
        std::fs::write(
            kh_dir.join("known_hosts"),
            format!("{} {}\n", self.addr, self.fingerprint),
        )
        .unwrap();
        home
    }
}

impl Drop for PrivsepServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Path to the real `quish` client binary, next to `CARGO_BIN_EXE_quishd`.
fn quish_client() -> PathBuf {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    if !quish.exists() {
        panic!(
            "quish client binary not found at {}; run `cargo build --workspace` first",
            quish.display()
        );
    }
    quish
}

/// Run the real `quish` client binary against `server`. The `server` borrow ties
/// the lifetime (so callers can't run a client after the server is dropped) and
/// supplies the cert fingerprint we pre-trust below.
fn run_client(server: &PrivsepServer, args: &[&str], password: Option<&str>) -> Output {
    let quish = quish_client();
    let home = server.client_home();
    let mut cmd = Command::new(&quish);
    cmd.args(args).env("HOME", &home);
    if let Some(p) = password {
        cmd.env("QUISH_PASSWORD", p);
    }
    cmd.output().expect("spawn quish client")
}

#[test]
#[ignore]
fn exec_runs_command_and_returns_output_privsep() {
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    let out = run_client(&server, &[&target, "echo", "quish-privsep-ok"], Some(&pw));

    assert!(out.status.success(), "client failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("quish-privsep-ok"),
        "unexpected stdout: {out:?}"
    );
}
