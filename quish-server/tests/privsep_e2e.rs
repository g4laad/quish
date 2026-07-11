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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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
        // The socket dir is `{chroot}.sock.d-{monitor-pid}`; the monitor we
        // spawned IS that pid (main -> monitor::run, same process). SIGKILL
        // skips the monitor's own cleanup (monitor.rs), so remove the leaked
        // dir ourselves — keeping /run clean for the next scenario.
        let pid = self.child.id();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(format!("/run/quishd.sock.d-{pid}"));
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

/// Spawn the real `quish` client in INTERACTIVE (shell) mode against `server`,
/// with piped stdin/stdout so a test can drive the PTY session from a pipe.
/// `run_client`'s `.output()` closes stdin immediately, which won't do for a
/// shell channel — hence this dedicated spawner.
fn spawn_interactive_client(server: &PrivsepServer, user: &str, password: &str) -> Child {
    let quish = quish_client();
    let home = server.client_home();
    Command::new(&quish)
        .arg(format!("{user}@{}", server.addr)) // no command => shell channel
        .env("HOME", &home)
        .env("QUISH_PASSWORD", password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn interactive quish client")
}

#[test]
#[ignore]
fn wrong_password_is_denied_privsep() {
    // The dev backend accepts any password; real PAM must reject a wrong one.
    // This is what distinguishes the privsep/PAM path from dev mode.
    let user = test_user();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    let out = run_client(
        &server,
        &[&target, "echo", "should-not-run"],
        Some("not-the-pw"),
    );

    assert!(
        !out.status.success(),
        "client succeeded despite a wrong password: {out:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("should-not-run"),
        "command output leaked despite rejected auth: {out:?}"
    );
}

#[test]
#[ignore]
fn interactive_shell_runs_a_command_privsep() {
    // Drive the PTY shell channel from a pipe: RawMode is a no-op on non-tty
    // stdin, and the client's stdin pump forwards bytes to the remote PTY. A
    // PTY echoes input, so `pty-marker-` may appear twice (echo + command
    // output) — assert `contains`, not an exact match. Keep stdin OPEN: the
    // `exit\n` line terminates the shell (server sends ExitStatus, client exits
    // cleanly); closing stdin early aborts the channel before the shell runs.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();

    let mut child = spawn_interactive_client(&server, &user, &pw);
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(b"echo pty-marker-$$\nexit\n")
        .expect("write to client stdin");
    stdin.flush().expect("flush client stdin");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    let out = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(buf) => buf,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("interactive client produced no stdout within 10s");
        }
    };
    let status = child.wait().expect("wait interactive client");

    assert!(
        out.contains("pty-marker-"),
        "shell did not run the command (no marker); status={status:?}, stdout={out:?}"
    );
}

#[test]
#[ignore]
fn oversized_command_does_not_kill_the_monitor_privsep() {
    // Guards plan 001: a ~63 KiB argument is above the worker's 60 KiB
    // MAX_SPAWN_ARG_LEN cap (but below the ~2 MB argv limit), so the channel is
    // rejected. The monitor must survive so the NEXT request still works.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    let big = "x".repeat(63 * 1024);
    let out = run_client(&server, &[&target, "echo", &big], Some(&pw));
    assert!(
        !(out.status.success() && String::from_utf8_lossy(&out.stdout).contains(&big)),
        "oversized command was accepted (channel not rejected): status={:?}",
        out.status
    );

    // Same server: a normal exec must still succeed — proof the monitor survived.
    let out2 = run_client(&server, &[&target, "echo", "still-alive"], Some(&pw));
    assert!(
        out2.status.success(),
        "normal exec after oversized request failed: {out2:?}"
    );
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("still-alive"),
        "monitor did not survive the oversized request: {out2:?}"
    );
}

#[test]
#[ignore]
fn socket_dir_is_root_only_privsep() {
    // Guards plan 004: the control/signing socket dir is a root-owned, 0700
    // sibling of the chroot dir under /run — never on /tmp.
    use std::os::unix::fs::MetadataExt;

    let server = PrivsepServer::start();

    let mut matches: Vec<PathBuf> = std::fs::read_dir("/run")
        .expect("read_dir /run")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("quishd.sock.d-"))
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one /run/quishd.sock.d-* dir while the server is up, found: {matches:?}"
    );
    let dir = matches.pop().unwrap();
    let md = std::fs::metadata(&dir).expect("stat socket dir");
    assert!(md.is_dir(), "socket path is not a directory: {dir:?}");
    assert_eq!(md.uid(), 0, "socket dir not owned by uid 0: {dir:?}");
    assert_eq!(
        md.mode() & 0o777,
        0o700,
        "socket dir mode is {:o}, expected 0700: {dir:?}",
        md.mode() & 0o777
    );

    // No socket dir must live under the temp dir (sockets are off /tmp).
    let tmp = std::env::temp_dir();
    let stray: Vec<PathBuf> = std::fs::read_dir(&tmp)
        .expect("read_dir temp")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("quishd-"))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "found socket dir(s) under the temp dir (should be under /run): {stray:?}"
    );

    drop(server);
}

#[test]
#[ignore]
fn reap_does_not_wedge_the_monitor_privsep() {
    // Guards plan 003 (part 1): an exec that closes its stdout/stderr but keeps
    // running must not wedge the monitor's serial control loop. Pre-003 the
    // reap would wait() on a live child forever; a concurrent second exec would
    // then hang. Post-003 the second returns promptly.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    thread::scope(|s| {
        // First exec: closes stdout/stderr, then lingers briefly.
        let bg = s.spawn(|| {
            run_client(
                &server,
                &[&target, "sh", "-c", "exec >&- 2>&-; sleep 2"],
                Some(&pw),
            )
        });

        // Second exec on the SAME server, immediately: must return well before
        // the first thread's 2s sleep matters.
        let start = Instant::now();
        let out2 = run_client(&server, &[&target, "echo", "second-login"], Some(&pw));
        let elapsed = start.elapsed();

        assert!(
            out2.status.success()
                && String::from_utf8_lossy(&out2.stdout).contains("second-login"),
            "second exec failed (monitor may be wedged): {out2:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "second exec took {elapsed:?} (>5s): the monitor's control loop is wedged"
        );

        let _ = bg.join();
    });
}

#[test]
#[ignore]
fn disconnect_kills_the_session_privsep() {
    // Guards plan 003 (part 2): when the client disconnects, the monitor's
    // Close reap must SIGKILL the connection's sessions. A shell backgrounds a
    // uniquely-named `sleep 293`; after we kill the client, that marker must
    // die. The distinctive duration keeps pgrep from matching anything else.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();

    let mut child = spawn_interactive_client(&server, &user, &pw);
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");

    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.contains("started") {
                        let _ = tx.send(());
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Keep stdin OPEN so the shell stays live; background a marker process.
    stdin
        .write_all(b"sleep 293 & echo started\n")
        .expect("write to client stdin");
    stdin.flush().expect("flush client stdin");

    rx.recv_timeout(Duration::from_secs(10))
        .expect("shell never reported 'started'");

    // Simulate a disconnect: kill the client outright.
    child.kill().expect("kill client");
    let _ = child.wait();
    drop(stdin);
    let _ = reader.join();

    // The session's `sleep 293` must be reaped within a few seconds.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut gone = false;
    while Instant::now() < deadline {
        let matched = Command::new("pgrep")
            .args(["-u", &user, "-f", "sleep 293"])
            .status()
            .expect("run pgrep")
            .success();
        if !matched {
            gone = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        gone,
        "session process 'sleep 293' survived client disconnect (plan 003 teardown regressed)"
    );
}
