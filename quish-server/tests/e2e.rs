//! End-to-end tests against the real auth + channel path, using `quishd`'s
//! root-free dev mode (`--dev-insecure-user`) and the real `quish` client
//! binary. No privilege drop, no PAM, no root — safe to run in CI.
//!
//! `#[ignore]`d by default: these spawn the `quish` client binary, which
//! `cargo test -p quish-server` does not build. Run
//! `cargo build --workspace && cargo test -p quish-server --test e2e -- --ignored`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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
        Self::start_full(user, extra_args, &fresh_temp_dir("quishd-home"))
    }

    /// Like [`start`], but with a caller-supplied `$HOME` so a test can seed the
    /// server's `~/.config/quish/authorized_keys` before the daemon reads it.
    fn start_with_home(user: &str, home: &Path) -> DevServer {
        Self::start_full(user, &[], home)
    }

    fn start_full(user: &str, extra_args: &[&str], home: &Path) -> DevServer {
        let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));

        // quishd's tracing writer defaults to stdout (unlike the client, which
        // sets stderr), so the readiness line arrives on stdout.
        let mut cmd = Command::new(&quishd);
        cmd.args(["--listen", "127.0.0.1:0", "--dev-insecure-user", user])
            .args(extra_args)
            .env("HOME", home)
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
fn upload_writes_file() {
    let server = DevServer::start("testuser");
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();
    let dir = fresh_temp_dir("quish-upload");
    let src = dir.join("source.txt");
    let dest = dir.join("uploaded.txt");
    let body = b"quish-upload-smoke-marker\n";
    std::fs::write(&src, body).unwrap();
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("testuser@{ip}:{}", dest.to_str().unwrap()),
        ],
        Some("anything"),
    );
    assert!(out.status.success(), "upload failed: {out:?}");
    assert_eq!(std::fs::read(&dest).unwrap(), body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn cp_download_writes_into_directory() {
    let server = DevServer::start("testuser");
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();
    let src_dir = fresh_temp_dir("quish-dl-src");
    let src = src_dir.join("os-release");
    let marker = b"quish-download-marker\n";
    std::fs::write(&src, marker).unwrap();
    let dst_dir = fresh_temp_dir("quish-dl-dst");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("testuser@{ip}:{}", src.to_str().unwrap()),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some("anything"),
    );
    assert!(out.status.success(), "download failed: {out:?}");
    let landed = dst_dir.join("os-release");
    assert_eq!(std::fs::read(&landed).unwrap(), marker);
    let leftover: Vec<_> = std::fs::read_dir(&dst_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("quish-part"))
        .collect();
    assert!(leftover.is_empty(), "temp part left behind: {leftover:?}");
    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&dst_dir);
}

#[test]
#[ignore]
fn cp_download_missing_file_fails_cleanly() {
    let server = DevServer::start("testuser");
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();
    let dst_dir = fresh_temp_dir("quish-dl-missing");
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            &format!("testuser@{ip}:/nonexistent/quish-does-not-exist-xyz"),
            &format!("{}/", dst_dir.to_str().unwrap()),
        ],
        Some("anything"),
    );
    assert!(!out.status.success(), "expected nonzero exit: {out:?}");
    let entries: Vec<_> = std::fs::read_dir(&dst_dir).unwrap().collect();
    assert!(entries.is_empty(), "dest dir should be empty: {entries:?}");
    let _ = std::fs::remove_dir_all(&dst_dir);
}

#[test]
#[ignore]
fn cp_uploads_directory_recursively() {
    use std::os::unix::fs::PermissionsExt;
    let server = DevServer::start("testuser");
    let ip = server.addr.ip();
    let port = server.addr.port().to_string();
    let base = fresh_temp_dir("quish-tree");
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"bravo").unwrap();
    std::fs::set_permissions(src.join("a.txt"), std::fs::Permissions::from_mode(0o755)).unwrap();

    let dst = base.join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    let out = run_client(
        &server,
        &[
            "cp",
            "-P",
            &port,
            src.to_str().unwrap(),
            &format!("testuser@{ip}:{}/", dst.to_str().unwrap()),
        ],
        Some("anything"),
    );
    assert!(out.status.success(), "tree upload failed: {out:?}");
    let root = dst.join("src");
    assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(root.join("sub/b.txt")).unwrap(), b"bravo");
    assert!(root.join("empty").is_dir(), "empty dir not created");
    let mode = std::fs::metadata(root.join("a.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert!(mode & 0o100 != 0, "exec bit not propagated: {mode:o}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[ignore]
fn cp_rejects_two_remote_or_two_local() {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    let both_local = Command::new(&quish)
        .args(["cp", "-P", "1", "a", "b"])
        .env("HOME", fresh_temp_dir("quish-cp-reject-ll"))
        .output()
        .expect("spawn quish client");
    assert!(
        !both_local.status.success(),
        "both-local should fail: {both_local:?}"
    );
    let both_remote = Command::new(&quish)
        .args(["cp", "-P", "1", "h1:/x", "h2:/y"])
        .env("HOME", fresh_temp_dir("quish-cp-reject-rr"))
        .output()
        .expect("spawn quish client");
    assert!(
        !both_remote.status.success(),
        "both-remote should fail: {both_remote:?}"
    );
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

/// A `quish keygen`-generated identity, once its public line is installed in the
/// server user's `authorized_keys`, authenticates a real login end to end. This
/// exercises the full onboarding path the CLI now supports: generate → install
/// → connect with `-i`.
#[test]
#[ignore]
fn keygen_key_logs_in() {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    assert!(
        quish.exists(),
        "quish client binary not found; run `cargo build --workspace` first"
    );

    // Dev mode reads $HOME/.config/quish/authorized_keys, so give the server a
    // controlled HOME we can seed after generating the key.
    let server_home = fresh_temp_dir("quishd-home");
    let key_path = server_home.join(".config/quish/id_ed25519");

    // 1. Generate an identity via the client's keygen subcommand.
    let keygen = Command::new(&quish)
        .args(["keygen", "-o", key_path.to_str().unwrap()])
        .output()
        .expect("spawn quish keygen");
    assert!(keygen.status.success(), "keygen failed: {keygen:?}");
    let pub_line = String::from_utf8_lossy(&keygen.stdout)
        .lines()
        .next()
        .expect("keygen printed a public line")
        .to_string();
    assert!(
        pub_line.starts_with("ssh-ed25519 "),
        "unexpected keygen output: {pub_line}"
    );

    // 2. Install the public line as the server user's authorized_keys.
    let ak = server_home.join(".config/quish/authorized_keys");
    std::fs::create_dir_all(ak.parent().unwrap()).unwrap();
    std::fs::write(&ak, format!("{pub_line}\n")).unwrap();

    // 3. Start the dev server with that HOME and log in with the generated key.
    let server = DevServer::start_with_home("testuser", &server_home);
    let target = format!("testuser@{}", server.addr);
    let output = run_client(
        &server,
        &["-i", key_path.to_str().unwrap(), &target, "echo", "hi"],
        None,
    );

    assert!(
        output.status.success(),
        "pubkey login with generated key failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hi"),
        "unexpected stdout: {output:?}"
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

/// With forwarding disabled (the default — no `--allow-forward`), the server
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

/// With remote forwarding enabled, a `-R` remote forward exposes a client-side
/// service on a server-side loopback port: an inbound connection to the server
/// port is tunneled back to the client, which dials its local echo service, and
/// bytes round-trip.
#[test]
#[ignore]
fn remote_forward_roundtrips_when_enabled() {
    let echo_port = spawn_echo_server(); // client-side target dialed on each accept
    let rport = free_local_port(); // server-side listener port the client requests
    let server = DevServer::start_with_args("testuser", &["--allow-remote-forward"]);
    let target = format!("testuser@{}", server.addr);
    let spec = format!("{rport}:127.0.0.1:{echo_port}");

    let mut client = run_client_child(&server, &["-R", &spec, &target], Some("anything"));
    // Keep the client's stdin open so it stays in forward mode.
    let _stdin = client.stdin.take();

    let mut conn = connect_retry(rport, Duration::from_secs(10));
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"quish-remote-forward-roundtrip";
    conn.write_all(payload).expect("write to remote forward");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .expect("read echo back through remote forward");
    assert_eq!(&got, payload, "remote-forwarded bytes did not echo back");

    drop(conn);
    let _ = client.kill();
    let _ = client.wait();
}

/// With remote forwarding disabled (the default — no `--allow-remote-forward`),
/// the server must refuse the `RemoteForwardListen` channel and never bind the
/// requested port, so nothing ever listens on it.
#[test]
#[ignore]
fn remote_forward_refused_when_disabled() {
    let echo_port = spawn_echo_server();
    let rport = free_local_port();
    let server = DevServer::start("testuser"); // default: remote forwarding disabled
    let target = format!("testuser@{}", server.addr);
    let spec = format!("{rport}:127.0.0.1:{echo_port}");

    let mut client = run_client_child(&server, &["-R", &spec, &target], Some("anything"));
    let _stdin = client.stdin.take();

    // The server refuses the listener; poll the requested server-side port and
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

// ---- challenge / TOTP two-factor (plan 023) --------------------------------

/// A shared TOTP secret for the challenge tests: its base32 form (passed to
/// `quishd --dev-insecure-totp-secret`) and raw bytes (to compute a live code).
fn totp_secret() -> (String, Vec<u8>) {
    let raw = b"12345678901234567890".to_vec();
    (quish_auth::totp::encode_base32_secret(&raw), raw)
}

/// Like [`run_client`] but also supplies `QUISH_TOTP` for the second factor and
/// returns how long the whole client run took (to assert the anti-enumeration
/// floor). Mirrors `run_client`'s known-hosts seeding.
fn run_client_2fa(
    server: &DevServer,
    args: &[&str],
    password: &str,
    totp: Option<&str>,
) -> (Output, Duration) {
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
        .env("QUISH_PASSWORD", password);
    if let Some(t) = totp {
        cmd.env("QUISH_TOTP", t);
    }
    let start = Instant::now();
    let out = cmd.output().expect("spawn quish client");
    (out, start.elapsed())
}

/// A full two-round login (password + correct TOTP) authenticates and runs the
/// remote command.
#[test]
#[ignore]
fn totp_two_round_login_succeeds() {
    let (b32, raw) = totp_secret();
    let server =
        DevServer::start_with_args("testuser", &["--dev-insecure-totp-secret", b32.as_str()]);
    let target = format!("testuser@{}", server.addr);
    let code = format!("{:06}", quish_auth::totp::current_code(&raw));

    let (out, _) = run_client_2fa(&server, &[&target, "echo", "hello2fa"], "pw", Some(&code));
    assert!(out.status.success(), "two-factor login failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello2fa"),
        "remote command output missing after 2FA login: {out:?}"
    );
}

/// A wrong second factor is a terminal, uniform 401 — and the constant-time floor
/// still applies (round-one challenge + terminal Deny are each floored).
#[test]
#[ignore]
fn totp_wrong_code_fails_uniformly_and_is_floored() {
    let (b32, _raw) = totp_secret();
    let server =
        DevServer::start_with_args("testuser", &["--dev-insecure-totp-secret", b32.as_str()]);
    let target = format!("testuser@{}", server.addr);

    let (out, elapsed) = run_client_2fa(&server, &[&target, "echo", "nope"], "pw", Some("000000"));
    assert!(!out.status.success(), "wrong TOTP must fail: {out:?}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("nope"),
        "command output leaked despite failed second factor: {out:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "terminal Deny was not floored (elapsed {elapsed:?}); the FAIL_DELAY floor must survive the challenge path"
    );
}

/// ANTI-ENUMERATION (the load-bearing assertion): an invalid username and a
/// valid-username-with-wrong-TOTP produce indistinguishable observable behavior —
/// both get a challenge round, both terminate in an identical `authentication
/// failed`, and both are floored. Nothing reveals which account actually exists.
#[test]
#[ignore]
fn totp_anti_enumeration_valid_and_invalid_user_indistinguishable() {
    let (b32, _raw) = totp_secret();
    let server =
        DevServer::start_with_args("testuser", &["--dev-insecure-totp-secret", b32.as_str()]);

    // (valid user, right password, WRONG second factor)
    let valid_target = format!("testuser@{}", server.addr);
    let (valid_out, valid_elapsed) =
        run_client_2fa(&server, &[&valid_target, "echo", "x"], "pw", Some("000000"));

    // (INVALID user) — never provisioned; must be challenged and denied the same.
    let invalid_target = format!("ghostuser@{}", server.addr);
    let (invalid_out, invalid_elapsed) = run_client_2fa(
        &server,
        &[&invalid_target, "echo", "x"],
        "pw",
        Some("000000"),
    );

    // Both fail, neither opens a session.
    assert!(
        !valid_out.status.success(),
        "valid-wrong-2fa unexpectedly succeeded: {valid_out:?}"
    );
    assert!(
        !invalid_out.status.success(),
        "invalid user unexpectedly succeeded: {invalid_out:?}"
    );

    // Identical failure signature: the client saw a challenge then a plain 401 in
    // both cases and reports the same generic error.
    let valid_err = String::from_utf8_lossy(&valid_out.stderr);
    let invalid_err = String::from_utf8_lossy(&invalid_out.stderr);
    assert!(
        valid_err.contains("authentication failed"),
        "valid-wrong-2fa error not the generic failure: {valid_err}"
    );
    assert!(
        invalid_err.contains("authentication failed"),
        "invalid-user error not the generic failure: {invalid_err}"
    );

    // Both floored: neither took a distinguishable fast path.
    assert!(
        valid_elapsed >= Duration::from_millis(1500),
        "valid-wrong-2fa not floored: {valid_elapsed:?}"
    );
    assert!(
        invalid_elapsed >= Duration::from_millis(1500),
        "invalid-user not floored: {invalid_elapsed:?}"
    );
}

/// An `--allow-user` naming the login user lets an authenticated login through:
/// the allowlist is satisfied, so the exec channel opens and runs.
#[test]
#[ignore]
fn policy_allow_user_permits_login() {
    let server = DevServer::start_with_args("testuser", &["--allow-user", "testuser"]);
    let target = format!("testuser@{}", server.addr);

    let out = run_client(&server, &[&target, "echo", "hi"], Some("anything"));
    assert!(out.status.success(), "allowlisted login failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hi"),
        "remote command output missing for allowlisted user: {out:?}"
    );
}

/// A `--deny-user` refuses a user who otherwise authenticates. The denial is
/// indistinguishable from a bad credential: same generic `authentication
/// failed`, no policy-specific wording, and the constant-time floor still applies.
#[test]
#[ignore]
fn policy_deny_user_refuses_login() {
    let server = DevServer::start_with_args("testuser", &["--deny-user", "testuser"]);
    let target = format!("testuser@{}", server.addr);

    let (out, elapsed) = run_client_2fa(&server, &[&target, "echo", "nope"], "anything", None);
    assert!(!out.status.success(), "denied user must fail: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("nope"),
        "command output leaked despite policy denial: {out:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("authentication failed"),
        "policy denial did not present the generic auth failure: {err}"
    );
    let lower = err.to_lowercase();
    assert!(
        !lower.contains("policy") && !lower.contains("deny"),
        "policy denial leaked distinct wording to the client: {err}"
    );
    assert!(
        elapsed >= Duration::from_secs(1),
        "policy denial was not floored (elapsed {elapsed:?}); the FAIL_DELAY floor must apply"
    );
}

/// A non-empty `--allow-user` is an exhaustive allowlist: a user not named is
/// refused even after authenticating, identically to a bad credential.
#[test]
#[ignore]
fn policy_allowlist_excludes_other_users() {
    let server = DevServer::start_with_args("testuser", &["--allow-user", "not-testuser"]);
    let target = format!("testuser@{}", server.addr);

    let (out, elapsed) = run_client_2fa(&server, &[&target, "echo", "nope"], "anything", None);
    assert!(
        !out.status.success(),
        "user excluded by the allowlist must fail: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("nope"),
        "command output leaked despite allowlist exclusion: {out:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("authentication failed"),
        "allowlist exclusion did not present the generic auth failure: {err}"
    );
    assert!(
        elapsed >= Duration::from_secs(1),
        "allowlist exclusion was not floored (elapsed {elapsed:?})"
    );
}

/// A config-file alias resolves to a live server: write a `config.toml` with a
/// `[hosts.devbox]` block pointing at the spawned dev server, then run the
/// client as `quish devbox 'echo hi'` with `QUISH_CONFIG` set. The alias must
/// supply the host/port/user so the bare token connects and echoes `hi`.
#[test]
#[ignore]
fn config_alias_connects() {
    let server = DevServer::start("testuser");

    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    if !quish.exists() {
        panic!(
            "quish client binary not found at {}; run `cargo build --workspace` first",
            quish.display()
        );
    }

    // Client home with the dev server's ephemeral cert pre-trusted (TOFU seed),
    // so the non-interactive run does not block on an unknown-host prompt.
    let home = fresh_temp_dir("quish-client-home");
    let kh_dir = home.join(".config/quish");
    std::fs::create_dir_all(&kh_dir).unwrap();
    std::fs::write(
        kh_dir.join("known_hosts"),
        format!("{} {}\n", server.addr, server.fingerprint),
    )
    .unwrap();

    // A config aliasing `devbox` to the spawned server's host/port + user.
    let cfg_path = home.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[hosts.devbox]\nhost = \"{}\"\nport = {}\nuser = \"testuser\"\n",
            server.addr.ip(),
            server.addr.port(),
        ),
    )
    .unwrap();

    let output = Command::new(&quish)
        .args(["devbox", "echo", "hi"])
        .env("HOME", &home)
        .env("QUISH_CONFIG", &cfg_path)
        .env("QUISH_PASSWORD", "x")
        .output()
        .expect("spawn quish client");

    assert!(
        output.status.success(),
        "client did not exit successfully: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hi"),
        "unexpected stdout: {output:?}"
    );
}

/// A host block's `path` is honored by `quish cp` (regression for the bug where
/// cp always used the built-in `/quish` and ignored the block's `path`). The dev
/// server listens on a non-default secret path; the alias block names that same
/// path; the upload succeeds only if cp resolves `path` from the block.
#[test]
#[ignore]
fn cp_honors_host_block_path() {
    let server = DevServer::start_with_args("testuser", &["--path", "/custom"]);

    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    if !quish.exists() {
        panic!(
            "quish client binary not found at {}; run `cargo build --workspace` first",
            quish.display()
        );
    }

    // Client home: pre-trust the dev server's ephemeral cert (TOFU seed) so the
    // non-interactive run does not block on an unknown-host prompt.
    let home = fresh_temp_dir("quish-cp-path-home");
    let kh_dir = home.join(".config/quish");
    std::fs::create_dir_all(&kh_dir).unwrap();
    std::fs::write(
        kh_dir.join("known_hosts"),
        format!("{} {}\n", server.addr, server.fingerprint),
    )
    .unwrap();

    // Config aliasing `cpbox` to the server, INCLUDING the custom secret path.
    let cfg_path = home.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[hosts.cpbox]\nhost = \"{}\"\nport = {}\nuser = \"testuser\"\npath = \"/custom\"\n",
            server.addr.ip(),
            server.addr.port(),
        ),
    )
    .unwrap();

    // Upload a file through the alias. dst dir is a fresh temp dir the dev-mode
    // session (running as the current user, chdir'd to $HOME) can write to.
    let src_dir = fresh_temp_dir("quish-cp-path-src");
    let src_file = src_dir.join("payload.txt");
    std::fs::write(&src_file, b"cp-path-ok").unwrap();
    let dst_dir = fresh_temp_dir("quish-cp-path-dst");
    let remote_dst = format!("cpbox:{}/", dst_dir.display());

    let output = Command::new(&quish)
        .args(["cp", src_file.to_str().unwrap(), &remote_dst])
        .env("HOME", &home)
        .env("QUISH_CONFIG", &cfg_path)
        .env("QUISH_PASSWORD", "x")
        .output()
        .expect("spawn quish cp");

    assert!(
        output.status.success(),
        "cp through alias with custom path did not succeed \
         (host block `path` likely ignored): {output:?}"
    );
    let landed = dst_dir.join("payload.txt");
    assert_eq!(
        std::fs::read(&landed).unwrap(),
        b"cp-path-ok",
        "uploaded file did not land at {}",
        landed.display()
    );
}

// ---- OIDC bearer (plan 027) ------------------------------------------------

/// The fixed issuer/audience/kid the test IdP mints under; the server config
/// (written by [`oidc_setup`]) must echo them, and every minted claim set too.
const OIDC_ISS: &str = "https://issuer.example";
const OIDC_AUD: &str = "quish";
const OIDC_KID: &str = "k1";

/// base64url without padding, the encoding the OIDC backend (and JWTs) expect.
fn oidc_b64url(bytes: &[u8]) -> String {
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Seconds since the Unix epoch, for `iat`/`exp` claims.
fn oidc_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A hand-minted compact EdDSA JWT. Deliberately hand-rolled — no `jsonwebtoken`
/// signer (the server's custom EdDSA provider deliberately has none): build the
/// header + claims JSON, base64url each, sign the `header.payload` bytes with
/// `ed25519-dalek`, then append base64url(sig). Mirrors the minting technique in
/// `quish-auth/src/oidc.rs`'s test module.
fn mint_jwt(signing: &ed25519_dalek::SigningKey, kid: &str, claims: &serde_json::Value) -> String {
    use ed25519_dalek::Signer;
    let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let h = oidc_b64url(&serde_json::to_vec(&header).unwrap());
    let p = oidc_b64url(&serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = signing.sign(signing_input.as_bytes());
    format!("{h}.{p}.{}", oidc_b64url(&sig.to_bytes()))
}

/// Provision a one-key OKP JWKS file plus a server TOML config carrying a
/// matching `[oidc]` table, and return `(config_path, signing_key)`. The server
/// re-reads the JWKS on every attempt, so the file must outlive the daemon — it
/// lives in a fresh temp dir that persists for the test.
fn oidc_setup() -> (PathBuf, ed25519_dalek::SigningKey) {
    let dir = fresh_temp_dir("quishd-oidc");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = signing.verifying_key().to_bytes();
    let jwks = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"{OIDC_KID}","x":"{}"}}]}}"#,
        oidc_b64url(&pubkey)
    );
    let jwks_path = dir.join("jwks.json");
    std::fs::write(&jwks_path, jwks).unwrap();
    let cfg_path = dir.join("server.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[oidc]\nissuer = \"{OIDC_ISS}\"\naudience = \"{OIDC_AUD}\"\njwks_file = \"{}\"\n",
            jwks_path.display()
        ),
    )
    .unwrap();
    (cfg_path, signing)
}

/// Like [`run_client`] but supplies `QUISH_OIDC_TOKEN` (the bearer) in place of a
/// password and returns the elapsed wall time (to assert the anti-enumeration
/// floor). Mirrors `run_client`'s known-hosts seeding.
fn run_client_oidc(server: &DevServer, args: &[&str], token: &str) -> (Output, Duration) {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    assert!(
        quish.exists(),
        "quish client binary not found; run `cargo build --workspace` first"
    );
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
        .env("QUISH_OIDC_TOKEN", token);
    let start = Instant::now();
    let out = cmd.output().expect("spawn quish client");
    (out, start.elapsed())
}

/// A valid bearer token whose `preferred_username` maps to the current OS user
/// authenticates a login and runs the remote command. The dev server is started
/// with `--dev-insecure-user $USER` AND `--config <toml>`, proving the `[oidc]`
/// table is honored in dev mode.
#[test]
#[ignore]
fn oidc_login_succeeds() {
    let user = std::env::var("USER").expect("USER env set");
    let (cfg, signing) = oidc_setup();
    let server = DevServer::start_with_args(&user, &["--config", cfg.to_str().unwrap()]);
    let target = format!("{user}@{}", server.addr);

    let claims = serde_json::json!({
        "iss": OIDC_ISS,
        "aud": OIDC_AUD,
        "sub": "abc",
        "preferred_username": user,
        "iat": oidc_now(),
        "exp": oidc_now() + 60,
    });
    let token = mint_jwt(&signing, OIDC_KID, &claims);

    let (out, _) = run_client_oidc(&server, &[&target, "echo", "hi"], &token);
    assert!(out.status.success(), "OIDC bearer login failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hi"),
        "remote command output missing after OIDC login: {out:?}"
    );
}

/// A bad bearer token fails exactly like a bad credential: the same generic
/// `authentication failed`, never a token-specific reason, and the constant-time
/// floor still applies. Both an EXPIRED token and a WRONG-AUDIENCE token are
/// checked — the two most likely to tempt a distinguishable error. Mirrors
/// `totp_wrong_code_fails_uniformly_and_is_floored`.
#[test]
#[ignore]
fn oidc_bad_token_fails_uniformly() {
    let user = std::env::var("USER").expect("USER env set");
    let (cfg, signing) = oidc_setup();
    let server = DevServer::start_with_args(&user, &["--config", cfg.to_str().unwrap()]);
    let target = format!("{user}@{}", server.addr);

    // Baseline: a wrong credential (login as a user the dev backend won't accept)
    // yields the generic failure the bad tokens must match verbatim.
    let (baseline, _) = run_client_2fa(
        &server,
        &[&format!("ghost@{}", server.addr), "echo", "x"],
        "pw",
        None,
    );
    assert!(!baseline.status.success());
    let baseline_err = String::from_utf8_lossy(&baseline.stderr).trim().to_string();
    assert!(
        baseline_err.contains("authentication failed"),
        "baseline wrong-credential error unexpected: {baseline_err}"
    );

    let expired = mint_jwt(
        &signing,
        OIDC_KID,
        &serde_json::json!({
            "iss": OIDC_ISS,
            "aud": OIDC_AUD,
            "sub": "abc",
            "preferred_username": user,
            "iat": oidc_now() - 7200,
            "exp": oidc_now() - 3600,
        }),
    );
    let wrong_aud = mint_jwt(
        &signing,
        OIDC_KID,
        &serde_json::json!({
            "iss": OIDC_ISS,
            "aud": "someone-else",
            "sub": "abc",
            "preferred_username": user,
            "iat": oidc_now(),
            "exp": oidc_now() + 60,
        }),
    );

    for (label, token) in [("expired", &expired), ("wrong-audience", &wrong_aud)] {
        let (out, elapsed) = run_client_oidc(&server, &[&target, "echo", "nope"], token);
        assert!(!out.status.success(), "{label} token must fail: {out:?}");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("nope"),
            "{label}: command output leaked despite failed auth: {out:?}"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            err.trim(),
            baseline_err,
            "{label}: error differs from the generic wrong-credential failure (leak)"
        );
        let lower = err.to_lowercase();
        assert!(
            !lower.contains("expired")
                && !lower.contains("audience")
                && !lower.contains("issuer")
                && !lower.contains("jwt")
                && !lower.contains("token"),
            "{label}: error leaked the token failure cause: {err}"
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "{label}: failure was not floored (elapsed {elapsed:?})"
        );
    }
}

/// Regression: enabling `[oidc]` must not eat pubkey logins. The JWT
/// dot-discrimination only diverts `Bearer` values containing a `.`; an `-i`
/// pubkey login against the SAME `[oidc]`-enabled server config still succeeds.
/// Models `keygen_key_logs_in`, adding `--config`.
#[test]
#[ignore]
fn pubkey_still_works_with_oidc_enabled() {
    let quishd = PathBuf::from(env!("CARGO_BIN_EXE_quishd"));
    let quish = quishd.with_file_name("quish");
    assert!(
        quish.exists(),
        "quish client binary not found; run `cargo build --workspace` first"
    );

    let server_home = fresh_temp_dir("quishd-home");
    let key_path = server_home.join(".config/quish/id_ed25519");

    let keygen = Command::new(&quish)
        .args(["keygen", "-o", key_path.to_str().unwrap()])
        .output()
        .expect("spawn quish keygen");
    assert!(keygen.status.success(), "keygen failed: {keygen:?}");
    let pub_line = String::from_utf8_lossy(&keygen.stdout)
        .lines()
        .next()
        .expect("keygen printed a public line")
        .to_string();

    let ak = server_home.join(".config/quish/authorized_keys");
    std::fs::create_dir_all(ak.parent().unwrap()).unwrap();
    std::fs::write(&ak, format!("{pub_line}\n")).unwrap();

    let (cfg, _signing) = oidc_setup();
    let server = DevServer::start_full(
        "testuser",
        &["--config", cfg.to_str().unwrap()],
        &server_home,
    );
    let target = format!("testuser@{}", server.addr);
    let output = run_client(
        &server,
        &["-i", key_path.to_str().unwrap(), &target, "echo", "hi"],
        None,
    );

    assert!(
        output.status.success(),
        "pubkey login failed with [oidc] enabled: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hi"),
        "unexpected stdout: {output:?}"
    );
}
