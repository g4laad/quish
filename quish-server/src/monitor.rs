//! The monitor: the root parent process. Owns the host private key (signs via a
//! proxy so it never reaches the worker), the auth registry (PAM + pubkey), and
//! session spawning. Re-execs the worker and serves its control + signing RPCs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

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

    // Private socket directory (root, 0700).
    let sock_dir = std::env::temp_dir().join(format!("quishd-{}", std::process::id()));
    std::fs::create_dir_all(&sock_dir).context("socket dir")?;
    std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o700))?;
    let ctrl_path = sock_dir.join("ctrl");
    let sign_path = sock_dir.join("sign");

    // Signing channel: blocking UnixListener; a thread signs with the host key.
    let sign_listener = UnixListener::bind(&sign_path).context("bind sign socket")?;
    spawn_sign_thread(sign_listener, signing_key);

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

/// Blocking signing loop: proxy each worker signature request to the host key.
fn spawn_sign_thread(listener: UnixListener, key: Arc<dyn SigningKey>) {
    std::thread::spawn(move || {
        // One worker → one sign connection; loop to tolerate reconnects.
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            loop {
                let req: SignRequest = match ipc::sign_read(&mut stream) {
                    Ok(Some(r)) => r,
                    _ => break,
                };
                let resp = match sign_with(&key, req.scheme, &req.message) {
                    Some(sig) => SignResponse::Signature(sig),
                    None => SignResponse::Failed,
                };
                if ipc::sign_write(&mut stream, &resp).is_err() {
                    break;
                }
            }
        }
    });
}

fn sign_with(key: &Arc<dyn SigningKey>, scheme: u16, message: &[u8]) -> Option<Vec<u8>> {
    let scheme = SignatureScheme::from(scheme);
    let signer = key.choose_scheme(&[scheme])?;
    signer.sign(message).ok()
}

/// State the monitor keeps for the (single) worker connection.
#[derive(Default)]
struct State {
    /// conn_id → authenticated username (identity is monitor-owned).
    users: HashMap<u64, String>,
    /// session_id → spawned child (for reaping).
    sessions: HashMap<u64, Child>,
    next_session: u64,
}

async fn serve_control(mut listener: UnixSeqpacketListener, registry: Arc<Registry>) -> Result<()> {
    let sock = listener.accept().await.context("accept worker ctrl")?;
    let mut st = State::default();

    while let Some((req, _fds)) = ipc::ctrl_recv::<Request>(&sock).await? {
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

            Request::SpawnShell {
                conn_id,
                term,
                cols: _,
                rows: _,
            } => {
                let reply = match st.users.get(&conn_id).cloned() {
                    Some(user) => match spawn_shell(&user, &term) {
                        Ok((child, master)) => {
                            let id = st.alloc(child);
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
                            let id = st.alloc(child);
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
                    Some(mut child) => {
                        let code = tokio::task::spawn_blocking(move || {
                            child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
                        })
                        .await
                        .unwrap_or(-1);
                        Response::Exited(code)
                    }
                    None => Response::Failed,
                };
                ipc::ctrl_send(&sock, &reply, &[]).await?;
            }

            Request::Close { conn_id } => {
                st.users.remove(&conn_id);
                ipc::ctrl_send(&sock, &Response::Closed, &[]).await?;
            }
        }
    }

    info!("worker control channel closed; monitor exiting");
    Ok(())
}

impl State {
    fn alloc(&mut self, child: Child) -> u64 {
        self.next_session += 1;
        let id = self.next_session;
        self.sessions.insert(id, child);
        id
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
