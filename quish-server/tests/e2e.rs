//! End-to-end tests against the real auth + channel path, using `quishd`'s
//! root-free dev mode (`--dev-insecure-user`) and the real `quish` client
//! binary. No privilege drop, no PAM, no root — safe to run in CI.
//!
//! `#[ignore]`d by default: these spawn the `quish` client binary, which
//! `cargo test -p quish-server` does not build. Run
//! `cargo build --workspace && cargo test -p quish-server --test e2e -- --ignored`.

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

/// A running dev-mode `quishd`, killed on drop so no daemon leaks if a test
/// panics.
struct DevServer {
    child: Child,
    addr: SocketAddr,
    fingerprint: String,
}

impl DevServer {
    fn start(user: &str) -> DevServer {
        Self::start_with_args(user, &[])
    }

    /// Like [`start`], but appends `extra_args` to the `quishd` argv (e.g.
    /// `--allow-forward`, which enables `-L` forwarding).
    fn start_with_args(user: &str, extra_args: &[&str]) -> DevServer {
        let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
        let home = fresh_temp_dir("quishd-home");

        // quishd's tracing writer defaults to stdout (unlike the client, which
        // sets stderr), so the readiness line arrives on stdout.
        let mut cmd = Command::new(&quishd);
        cmd.args(["--listen", "127.0.0.1:0", "--dev-insecure-user", user])
            .args(extra_args)
            .env("HOME", &home)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn quishd");

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

/// Like [`run_client`] but returns the live [`Child`] so the test can signal it
/// mid-run. stdin is `/dev/null`, stdout/stderr are captured; the caller waits.
fn run_client_child(server: &DevServer, args: &[&str], password: Option<&str>) -> Child {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    if !quish.exists() {
        panic!(
            "quish client binary not found at {}; run `cargo build --workspace` first",
            quish.display()
        );
    }

    let home = fresh_temp_dir("quish-client-home");
    let kh_dir = home.join(".config/quish");
    std::fs::create_dir_all(&kh_dir).unwrap();
    std::fs::write(
        kh_dir.join("known_hosts"),
        format!("{} {}\n", server.addr, server.fingerprint),
    )
    .unwrap();
    let mut cmd = Command::new(&quish);
    cmd.args(args)
        .env("HOME", &home)
        // Pipe stdin so the caller can hold it open (a real TTY never EOFs); an
        // EOF would make the client half-close its send stream mid-run.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = password {
        cmd.env("QUISH_PASSWORD", p);
    }
    cmd.spawn().expect("spawn quish client")
}

/// Ctrl-C on an exec channel must reach the *remote* process, not just kill the
/// local client. The client traps SIGINT and forwards a `Signal` frame; the
/// server delivers it to the remote command's process, whose own INT trap runs
/// and exits 42. The client then reports that remote status — proving the signal
/// made the full round trip rather than the client dying on the signal.
#[test]
#[ignore]
fn exec_signal_interrupts_remote() {
    let server = DevServer::start("testuser");
    let target = format!("testuser@{}", server.addr);

    // Remote command reacts to SIGINT within one 100ms tick (the pending trap
    // runs once the in-flight `sleep` returns) and exits 42.
    let mut child = run_client_child(
        &server,
        &[&target, "trap 'exit 42' INT; while :; do sleep 0.1; done"],
        Some("anything"),
    );
    // Keep the client's stdin open (as a real TTY is): on stdin EOF the client
    // half-closes its send stream and could no longer forward the signal frame.
    let _stdin = child.stdin.take();

    // Let the client connect and open the channel, then simulate Ctrl-C by
    // sending the client process SIGINT. The client forwards it and does not die.
    thread::sleep(Duration::from_millis(1500));
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).expect("send SIGINT to client");

    let status = child.wait().expect("wait for client");
    assert_eq!(
        status.code(),
        Some(42),
        "remote INT trap did not run; client status: {status:?}"
    );
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

/// A throwaway loopback TCP echo server: echoes every byte back until the peer
/// closes. Returns its bound port; the accept loop runs on a detached thread
/// (leaked for the test's lifetime, matching the stdout-drainer style above).
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

/// Grab a currently-free loopback port by binding ephemeral and releasing it.
/// (Small TOCTOU window, acceptable for a test.)
fn free_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Connect to `127.0.0.1:port`, retrying until the client's `-L` listener is up
/// or the deadline elapses.
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

/// With forwarding enabled, a `-L` local forward must tunnel loopback bytes:
/// local port → server → the remote loopback echo service and back.
#[test]
#[ignore]
fn local_forward_roundtrips_when_enabled() {
    let echo_port = spawn_echo_server();
    let lport = free_local_port();
    let server = DevServer::start_with_args("testuser", &["--allow-forward"]);
    let target = format!("testuser@{}", server.addr);
    let spec = format!("{lport}:127.0.0.1:{echo_port}");

    let mut client = run_client_child(&server, &["-L", &spec, &target], Some("anything"));
    // Keep the client's stdin open so it doesn't half-close and exit forward mode.
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(lport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"quish-forward-roundtrip";
    conn.write_all(payload).expect("write to forward");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .expect("read echo back through forward");
    assert_eq!(&got, payload, "forwarded bytes did not echo back");

    drop(conn);
    let _ = client.kill();
    let _ = client.wait();
}

/// With forwarding disabled (the default — no `QUISH_ALLOW_FORWARD`), the server
/// must refuse the forward channel: the local connection opens but is closed
/// without ever reaching the echo service, so no bytes come back.
#[test]
#[ignore]
fn local_forward_refused_when_disabled() {
    let echo_port = spawn_echo_server();
    let lport = free_local_port();
    let server = DevServer::start("testuser"); // default: forwarding disabled
    let target = format!("testuser@{}", server.addr);
    let spec = format!("{lport}:127.0.0.1:{echo_port}");

    let mut client = run_client_child(&server, &["-L", &spec, &target], Some("anything"));
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(lport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"should-not-echo";
    let _ = conn.write_all(payload); // may succeed locally; the channel is refused
    let mut buf = vec![0u8; payload.len()];
    // Refused: the server closes the channel without connecting, the client shuts
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
