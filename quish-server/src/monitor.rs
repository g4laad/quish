//! The monitor: the root parent process. Owns the host private key (signs via a
//! proxy so it never reaches the worker), the auth registry (PAM + pubkey), and
//! session spawning. Re-execs the worker and serves its control + signing RPCs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::prelude::{BASE64_STANDARD, Engine};
use nix::fcntl::OFlag;
use nix::pty::{PtyMaster, grantpt, posix_openpt, ptsname_r, unlockpt};
use nix::unistd::User;
use quish_auth::pubkey::PubkeyBackend;
use quish_auth::{AuthBackend, ConnInfo, Registry, Verdict};
use rustls::SignatureScheme;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::SigningKey;
use tokio_seqpacket::UnixSeqpacketListener;
use tracing::{info, warn};

use crate::ipc::{self, Request, Response, SignRequest, SignResponse};

/// Monitor configuration, from CLI/args.
pub struct Config {
    pub listen: SocketAddr,
    pub path: String,
    pub chroot_dir: String,
    pub worker_user: String,
    pub host_key: Option<PathBuf>,
    pub max_auth_fails: u32,
    pub allow_forward: bool,
}

/// Run the monitor: generate the host key, wire up sockets, launch the worker,
/// and serve RPCs until it exits.
pub fn run(cfg: Config) -> Result<()> {
    // Host identity: self-signed ECDSA P-256 (client pins via TOFU). The key lives
    // here only — the worker gets the cert and a signing proxy.
    let (cert_der, key_der) = host_identity(cfg.host_key.as_deref())?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .context("loading host signing key")?;
    let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;

    let fingerprint = quish_proto::cert_fingerprint(&cert_der);
    info!(%fingerprint, "host certificate SHA-256 (pin as: localhost:PORT <fingerprint>)");

    // Root-only socket dir: a sibling of the chroot dir so it isn't exposed inside
    // the chroot. Created exclusively (fails if it already exists) so a local
    // attacker can't pre-create it and own the path our sockets live in.
    let sock_dir = socket_dir_for(&cfg.chroot_dir);
    prepare_socket_dir(&sock_dir)?;
    let ctrl_path = sock_dir.join("ctrl");
    let sign_path = sock_dir.join("sign");

    // Signing channel: blocking UnixListener; a thread signs with the host key.
    let sign_listener = UnixListener::bind(&sign_path).context("bind sign socket")?;
    spawn_sign_thread(sign_listener, signing_key, scheme);

    // Auth registry (pubkey per-user; PAM when compiled in).
    let registry = build_registry();
    let exe = std::env::current_exe().context("current_exe")?;

    // Everything below needs the reactor (seqpacket listener registers with it).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async move {
        let ctrl_listener = UnixSeqpacketListener::bind(&ctrl_path).context("bind ctrl socket")?;

        // Re-exec the worker with everything it needs.
        let worker = Command::new(&exe)
            .arg("--internal-worker")
            .env(ipc::ENV_CTRL_PATH, &ctrl_path)
            .env(ipc::ENV_SIGN_PATH, &sign_path)
            .env(ipc::ENV_LISTEN, cfg.listen.to_string())
            .env(ipc::ENV_PATH, &cfg.path)
            .env(ipc::ENV_CHROOT, &cfg.chroot_dir)
            .env(ipc::ENV_USER, &cfg.worker_user)
            .env(ipc::ENV_SIGN_SCHEME, u16::from(scheme).to_string())
            .env(ipc::ENV_MAX_AUTH_FAILS, cfg.max_auth_fails.to_string())
            .env(ipc::ENV_ALLOW_FORWARD, cfg.allow_forward.to_string())
            .env(ipc::ENV_CERT, BASE64_STANDARD.encode(&cert_der))
            .spawn()
            .context("spawning worker")?;
        info!(pid = worker.id(), "worker started");

        let mut worker = worker;
        let result = serve_control(ctrl_listener, registry).await;
        // Don't leave the worker holding the port if the monitor loop exits.
        let _ = worker.kill();
        let _ = worker.wait();
        result
    });

    let _ = std::fs::remove_dir_all(&sock_dir);
    result
}

/// Sibling-of-chroot socket dir, pid-suffixed to avoid colliding with a
/// concurrent instance. Absolute so the pre-chroot worker can reach it.
fn socket_dir_for(chroot_dir: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}.sock.d-{}",
        chroot_dir.trim_end_matches('/'),
        std::process::id()
    ))
}

/// Create `dir` exclusively, 0700, and verify it is root-owned. Fails closed if
/// the path already exists (a pre-existing dir is untrusted) unless it is a
/// root-owned dir left by a crashed prior run (then clear+recreate), or if it
/// isn't root-owned after creation.
fn prepare_socket_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        let meta = std::fs::symlink_metadata(dir).context("stat existing socket dir")?;
        if meta.uid() != 0 || !meta.file_type().is_dir() {
            anyhow::bail!(
                "socket dir {} exists and is not a root-owned directory; refusing",
                dir.display()
            );
        }
        std::fs::remove_dir_all(dir).context("clearing stale socket dir")?;
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir) // NOT recursive: fails if it already exists (exclusive)
        .with_context(|| format!("exclusively creating socket dir {}", dir.display()))?;
    let meta = std::fs::symlink_metadata(dir).context("stat new socket dir")?;
    if meta.uid() != 0 {
        anyhow::bail!(
            "socket dir {} is not root-owned after creation",
            dir.display()
        );
    }
    Ok(())
}

/// Load the persisted host key + cert (DER), or generate and persist a fresh
/// pair. Ephemeral (new each start) when `path` is `None`.
fn host_identity(path: Option<&Path>) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let Some(path) = path else {
        warn!("no --host-key: using an ephemeral host key (fingerprint changes each restart)");
        let (cert, key, _) = generate_identity()?;
        return Ok((cert, key));
    };

    let cert_path = path.with_extension("crt");
    if path.exists() && cert_path.exists() {
        let key = std::fs::read(path).context("reading host key")?;
        let cert = std::fs::read(&cert_path).context("reading host cert")?;
        return Ok((
            CertificateDer::from(cert),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        ));
    }

    let (cert, key, key_bytes) = generate_identity()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, &key_bytes).context("writing host key")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&cert_path, cert.as_ref()).context("writing host cert")?;
    info!(path = %path.display(), "generated + persisted host key");
    Ok((cert, key))
}

fn generate_identity() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generating host cert")?;
    let cert_der = cert.cert.der().clone();
    let key_bytes = cert.signing_key.serialize_der();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes.clone()));
    Ok((cert_der, key_der, key_bytes))
}

fn build_registry() -> Arc<Registry> {
    let pubkey: Box<dyn AuthBackend> =
        Box::new(PubkeyBackend::with_resolver(Box::new(per_user_keys)));
    #[cfg(feature = "pam")]
    let backends = vec![
        pubkey,
        Box::new(quish_auth::pam::PamBackend) as Box<dyn AuthBackend>,
    ];
    #[cfg(not(feature = "pam"))]
    let backends = vec![pubkey];
    Arc::new(Registry::new(backends, crate::FAIL_DELAY))
}

/// Resolve a user's `~/.config/quish/authorized_keys` (root reads any home).
fn per_user_keys(user: &str) -> Option<PathBuf> {
    let u = User::from_name(user).ok()??;
    Some(u.dir.join(".config/quish/authorized_keys"))
}

/// Burst capacity of the host-key signing token bucket. One legitimate full TLS
/// handshake needs exactly one signature, so this is far above any real signing
/// rate for an interactive-shell server.
const SIGN_BURST: u32 = 32;
/// Time to regain one signing token (~2 signatures/sec sustained). A compromised
/// worker can use the monitor as a signing oracle (inherent to any signing proxy);
/// this bounds the abuse throughput. Sized well above legitimate handshake rates.
const SIGN_REFILL: Duration = Duration::from_millis(500);
/// Emit an audit line every this many signatures served (journal volume signal).
const SIGN_AUDIT_INTERVAL: u64 = 100;

/// Single-thread token bucket guarding host-key signatures. The signing loop is a
/// dedicated serial thread, so no locking is needed.
struct SignThrottle {
    tokens: u32,
    last: Instant,
}

impl SignThrottle {
    fn new() -> Self {
        Self {
            tokens: SIGN_BURST,
            last: Instant::now(),
        }
    }

    /// Refill by whole tokens for the time elapsed since `last`, then try to spend
    /// one. Returns `true` if a signature is permitted.
    fn allow(&mut self, now: Instant) -> bool {
        let refill_ns = SIGN_REFILL.as_nanos();
        let elapsed_ns = now.saturating_duration_since(self.last).as_nanos();
        let gained = u32::try_from(elapsed_ns / refill_ns).unwrap_or(u32::MAX);
        if gained > 0 {
            self.tokens = self.tokens.saturating_add(gained).min(SIGN_BURST);
            // Advance `last` by exactly the intervals consumed so fractional
            // progress isn't discarded.
            let step = SIGN_REFILL.checked_mul(gained).unwrap_or(SIGN_REFILL);
            self.last = self.last.checked_add(step).unwrap_or(now);
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Blocking signing loop: proxy each worker signature request to the host key. The
/// scheme is pinned to `scheme` (the monitor's choice) — the worker cannot select it.
/// A token bucket bounds oracle-abuse throughput and every refusal is logged.
fn spawn_sign_thread(listener: UnixListener, key: Arc<dyn SigningKey>, scheme: SignatureScheme) {
    std::thread::spawn(move || {
        let mut throttle = SignThrottle::new();
        let mut signed: u64 = 0;
        // One worker -> one sign connection; loop to tolerate reconnects.
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            loop {
                let req: SignRequest = match ipc::sign_read(&mut stream) {
                    Ok(Some(r)) => r,
                    _ => break,
                };
                let resp = if !throttle.allow(Instant::now()) {
                    warn!(
                        "host-key signing rate limit exceeded; refusing (possible worker compromise)"
                    );
                    SignResponse::Failed
                } else {
                    match sign_with(&key, scheme, &req.message) {
                        Some(sig) => {
                            signed += 1;
                            if signed.is_multiple_of(SIGN_AUDIT_INTERVAL) {
                                info!(signed, "host-key signatures served (audit)");
                            }
                            SignResponse::Signature(sig)
                        }
                        None => SignResponse::Failed,
                    }
                };
                if ipc::sign_write(&mut stream, &resp).is_err() {
                    break;
                }
            }
        }
    });
}

fn sign_with(
    key: &Arc<dyn SigningKey>,
    scheme: SignatureScheme,
    message: &[u8],
) -> Option<Vec<u8>> {
    let signer = key.choose_scheme(&[scheme])?;
    signer.sign(message).ok()
}

/// Reverse index: which session ids belong to which connection. Kept separate
/// from the `Child` store so the bookkeeping is unit-testable without spawning.
#[derive(Default)]
struct SessionIndex {
    sessions_by_conn: HashMap<u64, Vec<u64>>,
}

impl SessionIndex {
    /// Record that `session_id` belongs to `conn_id`.
    fn insert(&mut self, conn_id: u64, session_id: u64) {
        self.sessions_by_conn
            .entry(conn_id)
            .or_default()
            .push(session_id);
    }

    /// Drain and return every session id tied to `conn_id`.
    fn take_conn(&mut self, conn_id: u64) -> Vec<u64> {
        self.sessions_by_conn.remove(&conn_id).unwrap_or_default()
    }

    /// Remove `session_id` from its connection's list (a normal reap).
    fn forget(&mut self, session_id: u64) {
        for sids in self.sessions_by_conn.values_mut() {
            sids.retain(|&s| s != session_id);
        }
    }
}

/// Terminate (if still alive) and reap a session child, returning its exit code.
/// Never blocks indefinitely: a child that closed its pipes but is still running
/// is signalled first, so the subsequent wait returns promptly.
async fn reap_child(mut child: Child) -> i32 {
    let pid = child.id();
    tokio::task::spawn_blocking(move || {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code().unwrap_or(-1);
        }
        let p = nix::unistd::Pid::from_raw(pid as i32);
        let _ = nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGHUP);
        let _ = nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGKILL);
        child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
    })
    .await
    .unwrap_or(-1)
}

/// State the monitor keeps for the (single) worker connection.
#[derive(Default)]
struct State {
    /// conn_id → authenticated username (identity is monitor-owned).
    users: HashMap<u64, String>,
    /// session_id → spawned child (for reaping).
    sessions: HashMap<u64, Child>,
    /// conn_id → its live session ids (for kill-on-close).
    conn_sessions: SessionIndex,
    next_session: u64,
}

async fn serve_control(mut listener: UnixSeqpacketListener, registry: Arc<Registry>) -> Result<()> {
    let sock = listener.accept().await.context("accept worker ctrl")?;
    let mut st = State::default();

    loop {
        let req = match ipc::ctrl_recv::<Request>(&sock).await? {
            ipc::Recv::Closed => break,
            ipc::Recv::Bad => continue, // skip a malformed request; keep serving
            ipc::Recv::Msg(req, _fds) => req,
        };
        match req {
            Request::Authenticate {
                conn_id,
                authorization,
                peer,
                channel_binding,
            } => {
                let conn = ConnInfo {
                    peer_addr: peer
                        .parse()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    channel_binding,
                };
                let verdict = registry.verdict(authorization.as_deref(), &conn).await;
                let allow = matches!(verdict, Verdict::Allow { .. });
                if let Verdict::Allow { user } = verdict {
                    info!(%conn_id, %user, "authenticated");
                    st.users.insert(conn_id, user);
                }
                ipc::ctrl_send(&sock, &Response::Verdict(allow), &[]).await?;
            }

            Request::SpawnShell { conn_id, term } => {
                let reply = match st.users.get(&conn_id).cloned() {
                    Some(user) => match spawn_shell(&user, &term) {
                        Ok((child, master)) => {
                            let id = st.alloc(conn_id, child);
                            ipc::ctrl_send(
                                &sock,
                                &Response::Spawned { session_id: id },
                                &[master.as_fd()],
                            )
                            .await?;
                            drop(master);
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "spawn shell failed");
                            Response::Failed
                        }
                    },
                    None => Response::Failed,
                };
                ipc::ctrl_send(&sock, &reply, &[]).await?;
            }

            Request::SpawnExec { conn_id, command } => {
                let reply = match st.users.get(&conn_id).cloned() {
                    Some(user) => match spawn_exec(&user, &command) {
                        Ok((child, io)) => {
                            let id = st.alloc(conn_id, child);
                            let [i, o, e] = &io;
                            ipc::ctrl_send(
                                &sock,
                                &Response::Spawned { session_id: id },
                                &[i.as_fd(), o.as_fd(), e.as_fd()],
                            )
                            .await?;
                            drop(io);
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "spawn exec failed");
                            Response::Failed
                        }
                    },
                    None => Response::Failed,
                };
                ipc::ctrl_send(&sock, &reply, &[]).await?;
            }

            Request::Reap { session_id } => {
                let reply = match st.sessions.remove(&session_id) {
                    Some(child) => {
                        // child already taken from `sessions`; drop it from the
                        // reverse index too so `Close` doesn't double-reap.
                        st.forget_session(session_id);
                        Response::Exited(reap_child(child).await)
                    }
                    None => Response::Failed,
                };
                ipc::ctrl_send(&sock, &reply, &[]).await?;
            }

            Request::Close { conn_id } => {
                st.users.remove(&conn_id);
                for sid in st.conn_sessions.take_conn(conn_id) {
                    if let Some(child) = st.sessions.remove(&sid) {
                        let _ = reap_child(child).await;
                    }
                }
                ipc::ctrl_send(&sock, &Response::Closed, &[]).await?;
            }

            Request::Signal { session_id, signal } => {
                if let Some(child) = st.sessions.get(&session_id) {
                    let pid = child.id() as i32;
                    let sig = match signal {
                        quish_proto::Signal::Int => nix::sys::signal::Signal::SIGINT,
                        quish_proto::Signal::Quit => nix::sys::signal::Signal::SIGQUIT,
                        quish_proto::Signal::Term => nix::sys::signal::Signal::SIGTERM,
                    };
                    // Signal the whole session process group (negative pid). The
                    // exec session helper setsid()s (Step 3) so pgid == pid and
                    // the target command dies even if the login shell wrapped it.
                    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), sig);
                }
                ipc::ctrl_send(&sock, &Response::Closed, &[]).await?;
            }
        }
    }

    info!("worker control channel closed; monitor exiting");
    Ok(())
}

impl State {
    fn alloc(&mut self, conn_id: u64, child: Child) -> u64 {
        self.next_session += 1;
        let id = self.next_session;
        self.sessions.insert(id, child);
        self.conn_sessions.insert(conn_id, id);
        id
    }

    /// Remove a reaped session from both the child store and the reverse index.
    fn forget_session(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
        self.conn_sessions.forget(session_id);
    }
}

/// Spawn an interactive shell for `user` on a fresh PTY. Returns the child (for
/// reaping) and the PTY master (its fd is passed to the worker).
fn spawn_shell(user: &str, term: &str) -> Result<(Child, PtyMaster)> {
    let u = crate::privdrop::lookup_user(user)?;
    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).context("posix_openpt")?;
    grantpt(&master).context("grantpt")?;
    unlockpt(&master).context("unlockpt")?;
    let slave_path = ptsname_r(&master).context("ptsname")?;

    let s0 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&slave_path)
        .context("open pts")?;
    let s1 = s0.try_clone()?;
    let s2 = s0.try_clone()?;

    let child = session_command(&u)
        .env(ipc::ENV_SESS_TERM, term)
        .env(ipc::ENV_SESS_TTY, &slave_path)
        .stdin(Stdio::from(s0))
        .stdout(Stdio::from(s1))
        .stderr(Stdio::from(s2))
        .spawn()
        .context("spawn shell session")?;
    Ok((child, master))
}

/// Spawn `command` for `user` with piped stdio. Returns the child and the three
/// pipe fds (stdin, stdout, stderr) passed to the worker.
fn spawn_exec(user: &str, command: &str) -> Result<(Child, [std::os::fd::OwnedFd; 3])> {
    let u = crate::privdrop::lookup_user(user)?;
    let mut child = session_command(&u)
        .env(ipc::ENV_SESS_COMMAND, command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn exec session")?;
    let i = child.stdin.take().context("no stdin")?;
    let o = child.stdout.take().context("no stdout")?;
    let e = child.stderr.take().context("no stderr")?;
    Ok((child, [i.into(), o.into(), e.into()]))
}

/// Base `--internal-run-session` command for `user` (identity envs common to
/// shell and exec).
fn session_command(u: &User) -> Command {
    let shell = if u.shell.as_os_str().is_empty() {
        "/bin/sh".to_string()
    } else {
        u.shell.display().to_string()
    };
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.arg("--internal-run-session")
        .env(ipc::ENV_SESS_UID, u.uid.as_raw().to_string())
        .env(ipc::ENV_SESS_GID, u.gid.as_raw().to_string())
        .env(ipc::ENV_SESS_USER, &u.name)
        .env(ipc::ENV_SESS_HOME, u.dir.display().to_string())
        .env(ipc::ENV_SESS_SHELL, shell);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_conn_returns_all_sessions() {
        let mut idx = SessionIndex::default();
        idx.insert(1, 10);
        idx.insert(1, 11);
        let mut got = idx.take_conn(1);
        got.sort_unstable();
        assert_eq!(got, vec![10, 11]);
        // draining removes the entry
        assert!(idx.take_conn(1).is_empty());
    }

    #[test]
    fn forget_removes_session_from_conn() {
        let mut idx = SessionIndex::default();
        idx.insert(1, 10);
        idx.insert(1, 11);
        idx.forget(10);
        assert_eq!(idx.take_conn(1), vec![11]);
    }

    #[test]
    fn take_conn_unknown_is_empty() {
        let mut idx = SessionIndex::default();
        assert!(idx.take_conn(99).is_empty());
    }

    #[test]
    fn exclusive_create_rejects_existing() {
        let d = std::env::temp_dir().join(format!("quish-sockdir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        // Second exclusive create must fail (EEXIST) — the anti-race guard.
        assert!(std::fs::DirBuilder::new().mode(0o700).create(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn socket_dir_is_sibling_of_chroot() {
        let d = socket_dir_for("/run/quishd");
        let s = d.to_string_lossy();
        assert!(s.starts_with("/run/quishd.sock.d-"), "got {s}");
        // A sibling, not a child of the chroot dir.
        assert_ne!(d.parent(), Some(Path::new("/run/quishd")));
    }

    #[test]
    fn sign_throttle_allows_burst_then_refuses() {
        let mut t = SignThrottle::new();
        let now = Instant::now();
        for i in 0..SIGN_BURST {
            assert!(t.allow(now), "burst token {i} should be allowed");
        }
        assert!(!t.allow(now), "over-burst request must be refused");
    }

    #[test]
    fn sign_throttle_refills_after_interval() {
        let mut t = SignThrottle::new();
        let now = Instant::now();
        for _ in 0..SIGN_BURST {
            assert!(t.allow(now));
        }
        assert!(!t.allow(now), "bucket is empty");
        // Exactly one refill interval later, exactly one token is back.
        let later = now + SIGN_REFILL;
        assert!(t.allow(later), "one token should have refilled");
        assert!(!t.allow(later), "only one token should have refilled");
    }
}
