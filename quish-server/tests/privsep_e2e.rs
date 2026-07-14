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
use std::net::{SocketAddr, TcpListener, TcpStream};
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
/// Root's password in the test container (see Containerfile, plan 020).
fn root_password() -> String {
    std::env::var("QUISH_TEST_ROOT_PASSWORD")
        .expect("QUISH_TEST_ROOT_PASSWORD must be set (see Containerfile)")
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
        Self::start_with_args(&[])
    }

    /// Like [`start`], but appends `extra` to the `quishd` argv (e.g.
    /// `--allow-forward`, which enables `-L` forwarding for the daemon).
    fn start_with_args(extra: &[&str]) -> PrivsepServer {
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
            .args(extra)
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

#[test]
#[ignore]
fn no_seccomp_flag_still_serves_privsep() {
    // Escape hatch: `--no-seccomp` puts the worker's seccomp filter in audit
    // (log-only) mode instead of enforcing. Every other scenario in this suite
    // runs with enforcement ON (the default), so those are the enforcing proof;
    // this test only needs to show the opt-out path still completes a session.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start_with_args(&["--no-seccomp"]);
    let target = format!("{user}@{}", server.addr);

    let out = run_client(&server, &[&target, "echo", "no-seccomp-ok"], Some(&pw));

    assert!(out.status.success(), "client failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no-seccomp-ok"),
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
            out2.status.success() && String::from_utf8_lossy(&out2.stdout).contains("second-login"),
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
    // Close reap must SIGKILL the whole session process GROUP (killpg), not just
    // the leader pid, so backgrounded jobs — even ones ignoring SIGHUP — are
    // reaped. A shell backgrounds a uniquely-named `sleep 293`; after we kill the
    // client, that marker must die. The distinctive duration keeps pgrep from
    // matching anything else.
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
    // `trap '' HUP` makes the shell (and the `sleep` it backgrounds, which inherits
    // the ignore) immune to SIGHUP, so the PTY-hangup / leader-only-kill path can
    // NOT reap the job. The marker then dies ONLY if the monitor's Close reap
    // signals the whole process GROUP with SIGKILL (killpg). This turns a timing-
    // dependent flake into a deterministic guard: it fails on a leader-only reap and
    // passes on a group reap.
    stdin
        .write_all(b"trap '' HUP; sleep 293 & echo started\n")
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

/// A loopback echo server (mirrors `e2e.rs::spawn_echo_server`): echoes back
/// whatever it reads on each accepted connection. Returns its bound port.
fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Grab a currently-free loopback port by binding ephemeral and releasing it
/// (mirrors `e2e.rs::free_local_port`; small TOCTOU window, fine for a test).
fn free_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Connect to `127.0.0.1:port`, retrying until the client's `-L` listener is up
/// or the deadline elapses (mirrors `e2e.rs::connect_retry`).
fn connect_retry(port: u16, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("no connect to local forward port {port} within {timeout:?}: {e}");
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Spawn the real `quish` client with a `-L` local forward against `server`,
/// stdin piped and held open so the client stays in forward mode (mirrors
/// `spawn_interactive_client`, but for a forwarding session).
fn spawn_forward_client(server: &PrivsepServer, user: &str, password: &str, spec: &str) -> Child {
    let quish = quish_client();
    let home = server.client_home();
    Command::new(&quish)
        .args(["-L", spec, &format!("{user}@{}", server.addr)])
        .env("HOME", &home)
        .env("QUISH_PASSWORD", password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forwarding quish client")
}

/// With `--allow-forward`, a `-L` local forward must tunnel loopback bytes
/// through the REAL daemon (root monitor + chrooted worker): local port →
/// worker → the remote loopback echo service and back. Proves the flag is
/// usable in privsep mode, not just dev mode.
#[test]
#[ignore]
fn local_forward_roundtrips_privsep() {
    let user = test_user();
    let pw = test_password();
    let echo_port = spawn_echo_server();
    let lport = free_local_port();
    let server = PrivsepServer::start_with_args(&["--allow-forward"]);
    let spec = format!("{lport}:127.0.0.1:{echo_port}");

    let mut client = spawn_forward_client(&server, &user, &pw, &spec);
    // Keep the client's stdin open so it doesn't half-close and exit forward mode.
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(lport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"quish-privsep-forward-roundtrip";
    conn.write_all(payload).expect("write to forward");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .expect("read echo back through forward");
    assert_eq!(&got, payload, "forwarded bytes did not echo back");

    drop(conn);
    let _ = client.kill();
    let _ = client.wait();
}

/// Default (no `--allow-forward`): the real worker must refuse the forward
/// channel — the local connection opens but is closed without reaching the echo
/// service, so we read EOF (0 bytes).
#[test]
#[ignore]
fn local_forward_refused_when_disabled_privsep() {
    let user = test_user();
    let pw = test_password();
    let echo_port = spawn_echo_server();
    let lport = free_local_port();
    let server = PrivsepServer::start(); // default: forwarding disabled
    let spec = format!("{lport}:127.0.0.1:{echo_port}");

    let mut client = spawn_forward_client(&server, &user, &pw, &spec);
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(lport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"should-not-echo";
    let _ = conn.write_all(payload); // may succeed locally; the channel is refused
    let mut buf = vec![0u8; payload.len()];
    // Refused: the worker closes the channel without connecting, the client shuts
    // the local socket, so we read EOF (0 bytes) and never the echoed payload.
    let n = conn.read(&mut buf).unwrap_or(0);
    assert_eq!(
        n,
        0,
        "forwarding is disabled but {n} bytes came back: {:?}",
        &buf[..n]
    );

    drop(conn);
    let _ = client.kill();
    let _ = client.wait();
}

/// Spawn the real `quish` client with a `-R` remote forward against `server`,
/// stdin piped and held open so the client stays in forward mode (mirrors
/// `spawn_forward_client`, but passes `-R` instead of `-L`).
fn spawn_remote_forward_client(
    server: &PrivsepServer,
    user: &str,
    password: &str,
    spec: &str,
) -> Child {
    let quish = quish_client();
    let home = server.client_home();
    Command::new(&quish)
        .args(["-R", spec, &format!("{user}@{}", server.addr)])
        .env("HOME", &home)
        .env("QUISH_PASSWORD", password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn remote-forwarding quish client")
}

/// With `--allow-remote-forward`, a `-R` remote forward must round-trip through
/// the REAL daemon under ENFORCING seccomp (the default): the worker binds a
/// loopback listener (`listen()`), accepts inbound connections (`accept4()`),
/// and bridges each back to the client, which dials its local echo service. If
/// the worker's seccomp allowlist lacked `SYS_listen`/`SYS_accept4` the worker
/// would be SIGSYS-killed and this round-trip would fail — that is the point of
/// running it in privsep mode rather than only in dev mode.
#[test]
#[ignore]
fn remote_forward_roundtrips_privsep() {
    let user = test_user();
    let pw = test_password();
    let echo_port = spawn_echo_server(); // client-side target dialed on each accept
    let rport = free_local_port(); // server-side listener port the client requests
    let server = PrivsepServer::start_with_args(&["--allow-remote-forward"]);
    let spec = format!("{rport}:127.0.0.1:{echo_port}");

    let mut client = spawn_remote_forward_client(&server, &user, &pw, &spec);
    // Keep the client's stdin open so it stays in forward mode.
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(rport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"quish-privsep-remote-forward-roundtrip";
    conn.write_all(payload).expect("write to remote forward");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .expect("read echo back through remote forward");
    assert_eq!(&got, payload, "remote-forwarded bytes did not echo back");

    drop(conn);
    let _ = client.kill();
    let _ = client.wait();
}

/// Default (no `--allow-remote-forward`): the real worker must refuse the
/// `RemoteForwardListen` channel and never bind the requested server-side port,
/// so nothing ever listens on it. (Unlike `-L`, the SERVER owns the bind, so a
/// refusal means the port never becomes connectable — poll rather than read EOF.)
#[test]
#[ignore]
fn remote_forward_refused_when_disabled_privsep() {
    let user = test_user();
    let pw = test_password();
    let echo_port = spawn_echo_server();
    let rport = free_local_port();
    let server = PrivsepServer::start(); // default: remote forwarding disabled
    let spec = format!("{rport}:127.0.0.1:{echo_port}");

    let mut client = spawn_remote_forward_client(&server, &user, &pw, &spec);
    let _stdin = client.stdin.take();

    // The worker refuses the listener; poll the requested server-side port and
    // confirm nothing ever binds it (a successful connect means the gate leaked).
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", rport)).is_ok() {
            panic!("remote forwarding is disabled but the server bound port {rport}");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = client.kill();
    let _ = client.wait();
}

#[test]
#[ignore]
fn download_streams_user_readable_file_privsep() {
    // Plan 011 happy path: a file the login user can read downloads correctly.
    use std::os::unix::fs::PermissionsExt;
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let contents = "quish-download-ok-marker\n";
    let path = std::env::temp_dir().join(format!("quish-dl-user-{}.txt", std::process::id()));
    std::fs::write(&path, contents).expect("write download file");
    // World-readable so the target user can open it (parent /tmp is 1777).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("chmod download file");

    let dst_dir = fresh_temp_dir("quish-dl-dst");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("{user}@{ip}:{}", path.to_str().unwrap()),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some(&pw),
    );
    let landed = dst_dir.join(path.file_name().unwrap());
    let got = std::fs::read_to_string(&landed).ok();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dst_dir);

    assert!(out.status.success(), "download failed: {out:?}");
    assert_eq!(
        got.as_deref(),
        Some(contents),
        "download did not write file contents: {out:?}"
    );
}

#[test]
#[ignore]
fn download_refuses_root_only_file_privsep() {
    // Plan 011 identity-boundary proof: a root-owned, mode-000 file. Root CAN
    // read it; the login user CANNOT. If the download succeeds or leaks content,
    // open() ran as root (or the worker), not the authed user — the exact bug
    // this plan exists to prevent.
    use std::os::unix::fs::PermissionsExt;
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let secret = "root-only-secret-should-not-leak\n";
    let path = std::env::temp_dir().join(format!("quish-dl-root-{}.txt", std::process::id()));
    std::fs::write(&path, secret).expect("write root-only file"); // created as root
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let dst_dir = fresh_temp_dir("quish-dl-root-dst");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("{user}@{ip}:{}", path.to_str().unwrap()),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some(&pw),
    );
    // Restore perms so cleanup can remove the file.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_file(&path);

    // The secret must appear in no downloaded file, and no temp part may linger.
    let mut leaked = false;
    let mut part_leftover = false;
    for entry in std::fs::read_dir(&dst_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().contains("quish-part") {
            part_leftover = true;
        }
        if let Ok(body) = std::fs::read_to_string(entry.path())
            && body.contains(secret.trim())
        {
            leaked = true;
        }
    }
    let _ = std::fs::remove_dir_all(&dst_dir);

    assert!(
        !out.status.success(),
        "download of a root-only file succeeded — open() ran as root, not the user: {out:?}"
    );
    assert!(
        !leaked,
        "root-only file contents leaked into the destination: {out:?}"
    );
    assert!(!part_leftover, ".quish-part temp left behind: {out:?}");
}

#[test]
#[ignore]
fn upload_writes_user_writable_file_privsep() {
    // Plan 018 happy path: uploading into a world-writable dir succeeds and the
    // created file is owned by the login user (the create/write ran AS the user,
    // not as root/worker).
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let dir = std::env::temp_dir().join(format!("quish-ul-user-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create upload dir");
    // World-writable so the target user can create a file inside it.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod dir 777");
    let dest = dir.join("uploaded.txt");

    let src = fresh_temp_dir("quish-ul-src").join("source.txt");
    let body = b"quish-upload-privsep-marker\n";
    std::fs::write(&src, body).expect("write source");

    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("{user}@{ip}:{}", dest.to_str().unwrap()),
        ],
        Some(&pw),
    );

    let contents = std::fs::read(&dest).ok();
    let uid = std::fs::metadata(&dest).ok().map(|m| m.uid());
    let _ = std::fs::remove_file(&dest);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(out.status.success(), "upload failed: {out:?}");
    assert_eq!(
        contents.as_deref(),
        Some(&body[..]),
        "uploaded contents differ: {out:?}"
    );
    assert_ne!(uid, Some(0), "file created as root, not the user: {out:?}");
}

#[test]
#[ignore]
fn upload_refuses_root_only_dir_privsep() {
    // Plan 018 identity-boundary proof: a root-owned, mode-0700 dir. Root CAN
    // create files in it; the login user CANNOT. If the upload succeeds or the
    // target file gets created, open(O_CREAT) ran as root (or the worker), not
    // the authed user — the exact bug this plan exists to prevent.
    use std::os::unix::fs::PermissionsExt;
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let dir = std::env::temp_dir().join(format!("quish-ul-root-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create root-only dir"); // created as root
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod dir 700");
    let dest = dir.join("should-not-be-created.txt");

    let src = fresh_temp_dir("quish-ul-root-src").join("source.txt");
    std::fs::write(&src, b"must-not-land\n").expect("write source");

    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("{user}@{ip}:{}", dest.to_str().unwrap()),
        ],
        Some(&pw),
    );

    let created = dest.exists();
    // Restore/loosen perms so cleanup can remove the tree.
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_file(&dest);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !out.status.success(),
        "upload into a root-only dir succeeded — open() ran as root, not the user: {out:?}"
    );
    assert!(
        !created,
        "target file was created despite the user lacking write on the dir: {out:?}"
    );
}

#[test]
#[ignore]
fn cp_uploads_directory_recursively_privsep() {
    // Identity-boundary proof for MkDir: a recursive folder upload into a
    // world-writable dir must create every remote directory AND file as the
    // login user (mkdir/open ran AS the user, not root/worker).
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let dst = std::env::temp_dir().join(format!("quish-tree-dst-{}", std::process::id()));
    std::fs::create_dir_all(&dst).expect("create dst dir");
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o777)).expect("chmod 777");

    let base = fresh_temp_dir("quish-tree-src");
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"bravo").unwrap();

    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("{user}@{ip}:{}/", dst.to_str().unwrap()),
        ],
        Some(&pw),
    );

    let root = dst.join("src");
    let a = std::fs::read(root.join("a.txt")).ok();
    let b = std::fs::read(root.join("sub/b.txt")).ok();
    let dir_uid = std::fs::metadata(&root).ok().map(|m| m.uid());
    let sub_uid = std::fs::metadata(root.join("sub")).ok().map(|m| m.uid());
    let file_uid = std::fs::metadata(root.join("a.txt")).ok().map(|m| m.uid());
    let _ = std::fs::remove_dir_all(&dst);
    let _ = std::fs::remove_dir_all(&base);

    assert!(out.status.success(), "tree upload failed: {out:?}");
    assert_eq!(
        a.as_deref(),
        Some(&b"alpha"[..]),
        "a.txt contents differ: {out:?}"
    );
    assert_eq!(
        b.as_deref(),
        Some(&b"bravo"[..]),
        "b.txt contents differ: {out:?}"
    );
    assert_ne!(dir_uid, Some(0), "remote root dir created as root: {out:?}");
    assert_ne!(sub_uid, Some(0), "remote sub dir created as root: {out:?}");
    assert_ne!(file_uid, Some(0), "uploaded file created as root: {out:?}");
}

#[test]
#[ignore]
fn cp_mkdir_refused_in_root_only_dir_privsep() {
    // Identity-boundary proof for MkDir: a root-owned, mode-0700 dir. Root COULD
    // mkdir inside it; the login user CANNOT. If the folder upload succeeds or
    // the remote dir gets created, mkdir() ran as root (or the worker), not the
    // authed user — the exact regression this helper mode must never have.
    use std::os::unix::fs::PermissionsExt;
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let dir = std::env::temp_dir().join(format!("quish-mkdir-root-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create root-only dir"); // created as root
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod dir 700");

    let base = fresh_temp_dir("quish-mkdir-src");
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"nope").unwrap();

    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("{user}@{ip}:{}/", dir.to_str().unwrap()),
        ],
        Some(&pw),
    );

    let created = dir.join("src").exists();
    // Restore/loosen perms so cleanup can remove the tree.
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        !out.status.success(),
        "folder upload into a root-only dir succeeded — mkdir ran as root, not the user: {out:?}"
    );
    assert!(
        !created,
        "remote dir was created despite the user lacking write on the parent: {out:?}"
    );
}

#[test]
#[ignore]
fn cp_download_relative_path_resolves_to_home_privsep() {
    // Proves the chdir-to-home fix: a RELATIVE remote path resolves against the
    // login user's home dir (like scp/sftp), not the daemon's cwd.
    use std::os::unix::fs::{PermissionsExt, chown};
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let u = nix::unistd::User::from_name(&user)
        .expect("getpwnam")
        .expect("login user exists");
    let marker = "quish-relative-home-marker\n";
    let rel_name = "quish-rel-test.txt";
    let path = u.dir.join(rel_name);
    std::fs::write(&path, marker).expect("write home file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    chown(&path, Some(u.uid.as_raw()), Some(u.gid.as_raw())).expect("chown to login user");

    let dst_dir = fresh_temp_dir("quish-rel-dst");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("{user}@{ip}:{rel_name}"),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some(&pw),
    );
    let landed = dst_dir.join(rel_name);
    let got = std::fs::read_to_string(&landed).ok();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dst_dir);

    assert!(
        out.status.success(),
        "relative-path download failed: {out:?}"
    );
    assert_eq!(
        got.as_deref(),
        Some(marker),
        "relative remote path did not resolve to the user's home: {out:?}"
    );
}

#[test]
#[ignore]
fn exec_runs_command_as_root_privsep() {
    // Invariant: root is a first-class login. The session/transfer helpers must
    // NOT grow a root refusal — the worker's root checks in `drop_to_worker`
    // (`user.uid.is_root()` bail + the `setuid(from_raw(0))` regain probe) are
    // WORKER-ONLY. A failure here means a refactor copied one of those into the
    // session path, silently breaking every root login.
    let pw = root_password();
    let server = PrivsepServer::start();
    let target = format!("root@{}", server.addr);

    let out = run_client(&server, &[&target, "id", "-u"], Some(&pw));

    assert!(out.status.success(), "client failed: {out:?}");
    // Exact trim, NOT `contains("0")` — that would pass for any uid ending in 0.
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "exec as root did not run as uid 0: {out:?}"
    );
}

#[test]
#[ignore]
fn interactive_shell_as_root_privsep() {
    // Invariant: root is a first-class login. The session helper must NOT grow a
    // root refusal (the worker's root checks in `drop_to_worker` are worker-only).
    // The interactive shell must run as uid 0 for a root login.
    let server = PrivsepServer::start();

    let mut child = spawn_interactive_client(&server, "root", &root_password());
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(b"echo shell-uid-$(id -u)\nexit\n")
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
        out.contains("shell-uid-0"),
        "root shell did not run as uid 0; status={status:?}, stdout={out:?}"
    );
}

#[test]
#[ignore]
fn upload_writes_root_file_privsep() {
    // Invariant: root is a first-class login. The transfer helper must NOT grow a
    // root refusal (the worker's root checks in `drop_to_worker` are worker-only).
    // /root is mode 0700 root-owned in the image, so only root can create there —
    // a successful write PROVES the create/write ran as root.
    use std::os::unix::fs::MetadataExt;
    let pw = root_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let src = fresh_temp_dir("quish-ul-root-src").join("source.txt");
    let body = b"quish-upload-root-marker\n";
    std::fs::write(&src, body).expect("write source");

    let dest = format!("/root/quish-e2e-root-upload-{}.txt", std::process::id());
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("root@{ip}:{dest}"),
        ],
        Some(&pw),
    );

    let contents = std::fs::read(&dest).ok();
    let uid = std::fs::metadata(&dest).ok().map(|m| m.uid());
    let _ = std::fs::remove_file(&dest);

    assert!(out.status.success(), "upload failed: {out:?}");
    assert_eq!(
        contents.as_deref(),
        Some(&body[..]),
        "uploaded contents differ: {out:?}"
    );
    assert_eq!(
        uid,
        Some(0),
        "uploaded file not owned by root — the write ran as the wrong identity: {out:?}"
    );
}

#[test]
#[ignore]
fn download_reads_root_only_file_privsep() {
    // Invariant: root is a first-class login. The transfer helper must NOT grow a
    // root refusal (the worker's root checks in `drop_to_worker` are worker-only).
    // A mode-0600 root-owned file is readable ONLY by root, so a successful
    // download PROVES open() ran as root (inverse of
    // `download_refuses_root_only_file_privsep`, which logs in as the non-root user).
    use std::os::unix::fs::PermissionsExt;
    let pw = root_password();
    let server = PrivsepServer::start();
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();

    let marker = "quish-root-download-marker\n";
    let path = std::env::temp_dir().join(format!("quish-e2e-root-dl-{}.txt", std::process::id()));
    std::fs::write(&path, marker).expect("write root-only file"); // created as root
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 600 root-only");

    let dst_dir = fresh_temp_dir("quish-dl-root-ok-dst");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("root@{ip}:{}", path.to_str().unwrap()),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some(&pw),
    );
    let landed = dst_dir.join(path.file_name().unwrap());
    let got = std::fs::read_to_string(&landed).ok();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dst_dir);

    assert!(
        out.status.success(),
        "root could not download a root-readable file: {out:?}"
    );
    assert!(
        got.as_deref().is_some_and(|s| s.contains(marker.trim())),
        "downloaded file missing the root marker: {out:?}"
    );
}

#[test]
#[ignore]
fn pubkey_auth_as_root_privsep() {
    // Invariant: root is a first-class login. Pubkey auth must work for root and
    // the session helper must NOT grow a root refusal (the worker's root checks in
    // `drop_to_worker` are worker-only). authorized_keys must be a REGULAR file —
    // the monitor's reader refuses symlinks.
    let keypath = fresh_temp_dir("quish-rootkey").join("id_ed25519");
    let keypath_str = keypath.to_str().unwrap().to_string();
    let keygen = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f", &keypath_str])
        .status()
        .expect("spawn ssh-keygen");
    assert!(keygen.success(), "ssh-keygen failed to generate a key");

    std::fs::create_dir_all("/root/.config/quish").expect("create /root/.config/quish");
    let authorized = "/root/.config/quish/authorized_keys";
    std::fs::copy(format!("{keypath_str}.pub"), authorized).expect("install root authorized_keys");

    let server = PrivsepServer::start();
    let target = format!("root@{}", server.addr);
    let out = run_client(&server, &["-i", &keypath_str, &target, "id", "-u"], None);

    // Remove the installed key BEFORE asserting so a failure can't leave it behind.
    let _ = std::fs::remove_file(authorized);

    assert!(out.status.success(), "pubkey auth as root failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "pubkey login as root did not run as uid 0: {out:?}"
    );
}

/// Count the login's currently-OPEN wtmp records for `user`: a login
/// (`USER_PROCESS`) record with no matching logout (`DEAD_PROCESS`) record.
/// `last` renders these as "still logged in" or (with no `/var/run/utmp` to
/// confirm liveness, as in the rootless image) "gone - no logout". `-w` keeps
/// full usernames so `starts_with` matches the untruncated login name.
fn count_open_login_records(user: &str) -> usize {
    let out = Command::new("last")
        .args(["-w", "-n", "200"])
        .output()
        .expect("run last");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter(|line| {
            line.starts_with(user)
                && (line.contains("still logged in") || line.contains("gone - no logout"))
        })
        .count()
}

#[test]
#[ignore]
fn pam_session_registers_a_shell_login_privsep() {
    // Plan 022, Step 5: a password shell login must run the PAM *session* stack
    // (`pam_open_session`) so the login registers with the host accounting, and
    // that session must be closed at logout (`pam_close_session`).
    //
    // Accounting signal: `pam_lastlog` writes a wtmp login record on session
    // open and a logout record on close. We assert an OPEN record appears for
    // the user while the shell is live (registration), and that it is gone
    // (closed) after logout+reap (un-registration). `who`/utmp is NOT used: the
    // rootless-podman image has no `/var/run/utmp` (and no logind), so `who` is
    // always empty here — wtmp via `pam_lastlog` is the portable signal. See the
    // plan's Decision record ("Verified via") for why logind/utmp are not
    // exercised in the container.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();

    let open_before = count_open_login_records(&user);

    let mut child = spawn_interactive_client(&server, &user, &pw);
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");

    // Reader thread: signal once the shell is up and running commands.
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.contains("QREADY") {
                        let _ = tx.send(());
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Keep stdin OPEN so the session stays live while we inspect wtmp.
    stdin
        .write_all(b"echo QREADY\n")
        .expect("write to client stdin");
    stdin.flush().expect("flush client stdin");
    rx.recv_timeout(Duration::from_secs(10))
        .expect("shell never reported QREADY");

    // Session is OPEN: pam_open_session -> pam_lastlog wrote a login record.
    let open_during = count_open_login_records(&user);
    eprintln!("open_before={open_before} open_during={open_during}");
    assert!(
        open_during > open_before,
        "PAM session did not register the shell login in wtmp \
         (open records {open_before} -> {open_during}); pam_open_session/pam_lastlog did not run"
    );

    // Log out: the shell `exit` ends the session -> monitor Reap -> the PAM
    // guard drops -> pam_close_session + pam_setcred(DELETE_CRED). We require the
    // client to exit cleanly and promptly, which proves the close path ran
    // without wedging the monitor (reap_does_not_wedge covers the same path).
    //
    // NOTE (un-registration signal): pam_lastlog writes only a *login* record to
    // wtmp, not a logout one, and this image has no logind — so there is no
    // observable accounting signal for session close here (every login leaves a
    // permanent "gone - no logout" wtmp record; hence `open_before` may be > 0).
    // Session close is therefore verified structurally (the guard's Drop runs
    // pam_close_session at Reap/Close) and by clean, non-wedging teardown, not
    // by a wtmp logout record. On a systemd host `pam_systemd` would remove the
    // logind session, giving an observable close signal (deferred; see plan 022).
    stdin
        .write_all(b"exit\n")
        .expect("write exit to client stdin");
    stdin.flush().expect("flush exit");

    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = child.wait();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("client did not exit within 10s after logout (close path wedged?)");
    drop(stdin);
    let _ = reader.join();
}

#[test]
#[ignore]
fn pam_session_registers_an_exec_privsep() {
    // Plan 022 Phase 2: an EXEC channel (`quish host cmd`, not an interactive
    // shell) must also run the PAM *session* stack (`pam_open_session`) so a
    // non-interactive login registers with host accounting exactly like a shell
    // login. This is the exec analogue of
    // `pam_session_registers_a_shell_login_privsep`.
    //
    // Accounting signal is wtmp via `pam_lastlog` (same as the shell test): we
    // background a long-ish exec and, while it is live, assert an OPEN login
    // record appears for the user above baseline. `who`/utmp and logind are not
    // usable in the rootless image (see that test / the plan's Decision record),
    // and session *close* has no observable wtmp signal here — it is verified
    // structurally via the guard's Drop (pam_close_session + DELETE_CRED at
    // Reap/Close), not by a logout record.
    let user = test_user();
    let pw = test_password();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    let open_before = count_open_login_records(&user);

    let open_during = thread::scope(|s| {
        // Background a long-ish exec so the PAM session stays open while we poll.
        let bg = s.spawn(|| run_client(&server, &[&target, "sleep", "3"], Some(&pw)));

        // Poll for the login record to appear: auth + spawn + open_session take a
        // moment. Give up after ~2s, comfortably inside the `sleep 3` window.
        let mut seen = open_before;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let now = count_open_login_records(&user);
            if now > open_before {
                seen = now;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let out = bg.join().expect("exec client thread panicked");
        assert!(out.status.success(), "backgrounded exec failed: {out:?}");
        seen
    });

    eprintln!("open_before={open_before} open_during={open_during}");
    assert!(
        open_during > open_before,
        "PAM session did not register the exec login in wtmp \
         (open records {open_before} -> {open_during}); pam_open_session/pam_lastlog did not run"
    );
}

#[test]
#[ignore]
fn pam_session_registers_a_pubkey_login_privsep() {
    // Plan 022 Phase 2 (Q2=A): the monitor opens the PAM session off `st.users`
    // by username, independent of the auth method — so a PUBKEY login registers
    // in host accounting just like a password login, with NO `pubkey.rs` change.
    // This proves that method-agnostic open for a pubkey exec channel.
    //
    // Same wtmp-via-pam_lastlog signal and live-window technique as the exec
    // test; same caveats apply (no utmp/logind in the image; session close has
    // no observable wtmp signal here, verified structurally via the guard Drop).
    let user = test_user();
    let server = PrivsepServer::start();
    let target = format!("{user}@{}", server.addr);

    // Generate an ed25519 key and install its public half as the test user's
    // authorized_keys. It must be a REGULAR file (the monitor's reader uses
    // O_NOFOLLOW and refuses non-regular files); a root-created regular file is
    // fine (no ownership check), mirroring `pubkey_auth_as_root_privsep`.
    let keypath = fresh_temp_dir("quish-userkey").join("id_ed25519");
    let keypath_str = keypath.to_str().unwrap().to_string();
    let keygen = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f", &keypath_str])
        .status()
        .expect("spawn ssh-keygen");
    assert!(keygen.success(), "ssh-keygen failed to generate a key");

    let kh_dir = format!("/home/{user}/.config/quish");
    std::fs::create_dir_all(&kh_dir).expect("create <home>/.config/quish");
    let authorized = format!("{kh_dir}/authorized_keys");
    std::fs::copy(format!("{keypath_str}.pub"), &authorized).expect("install user authorized_keys");

    let open_before = count_open_login_records(&user);

    let (out, open_during) = thread::scope(|s| {
        // Background a long-ish PUBKEY exec: `-i <key>`, NO password.
        let bg =
            s.spawn(|| run_client(&server, &["-i", &keypath_str, &target, "sleep", "3"], None));

        let mut seen = open_before;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let now = count_open_login_records(&user);
            if now > open_before {
                seen = now;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let out = bg.join().expect("pubkey exec client thread panicked");
        (out, seen)
    });

    // Remove the installed key BEFORE asserting so a failure can't leave it behind.
    let _ = std::fs::remove_file(&authorized);

    assert!(out.status.success(), "pubkey exec failed: {out:?}");
    eprintln!("open_before={open_before} open_during={open_during}");
    assert!(
        open_during > open_before,
        "PAM session did not register the pubkey login in wtmp \
         (open records {open_before} -> {open_during}); the monitor's method-agnostic \
         session open did not run for a pubkey login"
    );
}
