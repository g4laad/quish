//! QUIC/HTTP-3 accept loop, shared by dev mode and the privsep worker. Auth and
//! session spawning are abstracted behind [`Backend`] so the same transport
//! drives an in-process registry (dev) or the monitor RPC client (privsep).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quish_auth::{ChallengeResponse, ConnInfo, Registry, Verdict};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::{Instant, timeout};
use tracing::{info, warn};

use crate::ratelimit::RateLimiter;
use crate::worker::{MonitorClient, serve_channel};

/// Outcome of one authentication attempt as the transport presents it.
pub(crate) enum AuthOutcome {
    /// Authenticated: bind identity and serve the channel.
    Allow,
    /// Terminal failure: an identical `401`, floored to the constant-time delay.
    Deny,
    /// A further factor is needed: reply `401` + challenge header and keep the
    /// connection up for the client's follow-up CONNECT.
    Challenge(quish_proto::Challenge),
}

/// How long a parked challenge stays resumable before it is dropped.
pub(crate) const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// Per-connection challenge state for the dev (in-process) path; the privsep
/// monitor keeps its own equivalent in `State`. Keyed by the server-assigned
/// `conn_id` and bounded to ONE pending challenge per connection, so a challenge
/// can never be resumed on another connection and the map cannot grow unbounded.
#[derive(Default)]
pub(crate) struct ChallengeStore {
    inner: Mutex<HashMap<u64, (quish_auth::ChallengeState, Instant)>>,
}

impl ChallengeStore {
    /// Park a fresh challenge for `conn_id`, replacing any prior pending one.
    pub(crate) fn insert(&self, conn_id: u64, state: quish_auth::ChallengeState) {
        self.inner
            .lock()
            .expect("challenge store poisoned")
            .insert(conn_id, (state, Instant::now()));
    }

    /// Remove and return the parked challenge IF it belongs to `conn_id`, matches
    /// `token`, and has not expired. Any mismatch consumes the entry and fails
    /// (a wrong/stale token cannot be retried against the same parked state).
    pub(crate) fn take(&self, conn_id: u64, token: &str) -> Option<quish_auth::ChallengeState> {
        let (state, created) = self
            .inner
            .lock()
            .expect("challenge store poisoned")
            .remove(&conn_id)?;
        if created.elapsed() > CHALLENGE_TTL || state.token != token {
            return None;
        }
        Some(state)
    }

    /// Drop any parked challenge for a gone connection.
    pub(crate) fn clear(&self, conn_id: u64) {
        self.inner
            .lock()
            .expect("challenge store poisoned")
            .remove(&conn_id);
    }
}

/// QUIC idle timeout: reaps dead connections. Interactive shells survive it
/// because the client sends keep-alives well under this interval.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Max concurrent channels (bidi request streams) per connection.
const MAX_CHANNELS_PER_CONN: u32 = 16;
/// A fresh connection must send its first request within this window.
const FIRST_REQUEST_DEADLINE: Duration = Duration::from_secs(30);
/// Hard ceiling on how long one auth attempt may take (guards a hung monitor).
const AUTH_DEADLINE: Duration = Duration::from_secs(30);
/// Failed auths tolerated on one connection before further attempts are cheap-
/// rejected (the connection stays up; anti-enumeration is preserved). Overridable
/// via config file / `--max-auth-fails`; this is the built-in fallback.
pub(crate) const DEFAULT_MAX_AUTH_FAILS: u32 = 6;

/// QUIC transport limits shared by dev and privsep endpoints.
pub fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("valid idle timeout")));
    t.max_concurrent_bidi_streams(MAX_CHANNELS_PER_CONN.into());
    Arc::new(t)
}

/// How auth + session spawning are satisfied.
pub enum Backend {
    /// Single-process dev mode: in-process registry, local session spawn.
    Dev {
        registry: Arc<Registry>,
        challenges: ChallengeStore,
    },
    /// Privsep worker: everything goes to the monitor over RPC.
    Privsep { client: Arc<MonitorClient> },
}

impl Backend {
    /// Returns whether the connection is authenticated. Both paths present an
    /// identical outcome; the anti-enumeration floor is applied here for privsep
    /// (the monitor returns a raw verdict) and inside the registry for dev.
    async fn authenticate(
        &self,
        conn_id: u64,
        authorization: Option<&str>,
        answer: Option<&quish_proto::ChallengeAnswer>,
        conn: &ConnInfo,
    ) -> AuthOutcome {
        match self {
            Backend::Dev {
                registry,
                challenges,
            } => {
                let mut conn = conn.clone();
                // Resume a parked challenge if this request answers one.
                if let Some(ans) = answer {
                    conn.challenge = challenges
                        .take(conn_id, &ans.token)
                        .map(|state| ChallengeResponse::new(state, ans.responses.clone()));
                }
                match registry.authenticate(authorization, &conn).await {
                    Verdict::Allow { .. } => AuthOutcome::Allow,
                    Verdict::Challenge { state, prompts } => {
                        let token = state.token.clone();
                        challenges.insert(conn_id, state);
                        AuthOutcome::Challenge(quish_proto::Challenge { token, prompts })
                    }
                    Verdict::Deny => AuthOutcome::Deny,
                }
            }
            Backend::Privsep { client } => {
                let started = Instant::now();
                let outcome = client
                    .authenticate(conn_id, authorization, answer, conn)
                    .await
                    .unwrap_or(AuthOutcome::Deny);
                // The monitor returns a raw verdict; floor every non-success here
                // (terminal Deny AND the intermediate Challenge) so a slow first
                // factor never leaks account existence through response timing.
                if !matches!(outcome, AuthOutcome::Allow) {
                    tokio::time::sleep_until(started + client.fail_delay).await;
                }
                outcome
            }
        }
    }

    async fn serve(
        &self,
        conn_id: u64,
        stream: crate::session::FullStream,
        allow_forward: bool,
    ) -> Result<()> {
        match self {
            Backend::Dev { .. } => crate::session::serve(stream, allow_forward).await,
            Backend::Privsep { client } => {
                serve_channel(client, conn_id, stream, allow_forward).await
            }
        }
    }

    async fn close(&self, conn_id: u64) {
        match self {
            Backend::Dev { challenges, .. } => challenges.clear(conn_id),
            Backend::Privsep { client } => client.close(conn_id).await,
        }
    }
}

/// Build a dev endpoint with a fresh self-signed cert; logs the fingerprint for
/// TOFU pinning. (Privsep builds its own endpoint via the signing proxy.)
pub fn dev_endpoint(listen: SocketAddr) -> Result<quinn::Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generating self-signed cert")?;
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let fingerprint = quish_proto::cert_fingerprint(&cert_der);
    info!(%fingerprint, "server certificate SHA-256 (pin as: localhost:PORT <fingerprint>)");

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .context("building rustls server config")?;
    tls.alpn_protocols = vec![quish_proto::ALPN.to_vec()];

    let quic = QuicServerConfig::try_from(tls).context("quinn rustls config")?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quic));
    sc.transport_config(transport_config());
    quinn::Endpoint::server(sc, listen).context("binding endpoint")
}

/// Serve until the endpoint is closed.
pub async fn run(
    endpoint: quinn::Endpoint,
    path: String,
    backend: Arc<Backend>,
    max_auth_fails: u32,
    allow_forward: bool,
) -> Result<()> {
    info!(addr = ?endpoint.local_addr().ok(), %path, "quishd listening");

    let limiter = Arc::new(RateLimiter::default());
    static NEXT_CONN: AtomicU64 = AtomicU64::new(1);
    while let Some(incoming) = endpoint.accept().await {
        // Per-IP connection cap: reject before the handshake if over the limit.
        let Some(guard) = limiter.admit(incoming.remote_address().ip()) else {
            incoming.refuse();
            continue;
        };
        let path = path.clone();
        let backend = backend.clone();
        let limiter = limiter.clone();
        let conn_id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _guard = guard; // released when the connection ends
            if let Err(e) = handle_connection(
                incoming,
                path,
                backend.clone(),
                limiter,
                conn_id,
                max_auth_fails,
                allow_forward,
            )
            .await
            {
                warn!(error = %e, "connection ended with error");
            }
            backend.close(conn_id).await;
        });
    }
    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    path: String,
    backend: Arc<Backend>,
    limiter: Arc<RateLimiter>,
    conn_id: u64,
    max_auth_fails: u32,
    allow_forward: bool,
) -> Result<()> {
    let conn = incoming.await.context("QUIC handshake")?;
    let peer_addr = conn.remote_address();
    info!(%conn_id, peer = %peer_addr, "connection established");

    let mut channel_binding = [0u8; quish_proto::CHANNEL_BINDING_LEN];
    conn.export_keying_material(
        &mut channel_binding,
        quish_proto::CHANNEL_BINDING_LABEL,
        &[],
    )
    .map_err(|e| anyhow::anyhow!("exporting channel binding: {e:?}"))?;
    let conn_info = ConnInfo {
        peer_addr,
        channel_binding,
        challenge: None,
    };

    let mut h3conn = h3::server::builder()
        .enable_extended_connect(true)
        .build::<h3_quinn::Connection, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("h3 handshake")?;

    let conn_fails = Arc::new(AtomicU32::new(0));
    let mut first = true;
    loop {
        // Reap connect-and-idle: the first request must arrive promptly.
        let accepted = if first {
            match timeout(FIRST_REQUEST_DEADLINE, h3conn.accept()).await {
                Ok(r) => r,
                Err(_) => return Ok(()), // no request in time: drop quietly
            }
        } else {
            h3conn.accept().await
        };
        first = false;

        match accepted {
            Ok(Some(resolver)) => {
                let path = path.clone();
                let backend = backend.clone();
                let limiter = limiter.clone();
                let conn_info = conn_info.clone();
                let conn_fails = conn_fails.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(
                        resolver,
                        path,
                        backend,
                        limiter,
                        conn_info,
                        conn_id,
                        conn_fails,
                        max_auth_fails,
                        allow_forward,
                    )
                    .await
                    {
                        warn!(error = %e, "request ended with error");
                    }
                });
            }
            Ok(None) => return Ok(()),
            Err(e) if e.is_h3_no_error() => return Ok(()),
            Err(e) => return Err(anyhow::anyhow!("h3 accept: {e}")),
        }
    }
}

type ReqStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    path: String,
    backend: Arc<Backend>,
    limiter: Arc<RateLimiter>,
    conn_info: ConnInfo,
    conn_id: u64,
    conn_fails: Arc<AtomicU32>,
    max_auth_fails: u32,
    allow_forward: bool,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolving request")?;

    let is_quish = req.method() == Method::CONNECT
        && req.extensions().get::<Protocol>().is_some()
        && req.uri().path() == path;
    if !is_quish {
        respond(&mut stream, StatusCode::NOT_FOUND).await?;
        return stream.finish().await.map_err(Into::into);
    }

    // Documented discriminator: reject an unsupported protocol version with a
    // clear status, before any auth work. Placed AFTER the secret-path check so
    // a wrong path still gets the generic 404 (path stays unguessable).
    let version = req
        .headers()
        .get(quish_proto::HEADER_VERSION)
        .and_then(|v| v.to_str().ok());
    if !quish_proto::version_supported(version) {
        warn!(%conn_id, ?version, "unsupported quish-version");
        respond(&mut stream, StatusCode::UPGRADE_REQUIRED).await?;
        return stream.finish().await.map_err(Into::into);
    }

    let ip = conn_info.peer_addr.ip();

    // A connection that keeps failing auth gets cheap 401s (no monitor round-trip)
    // once over the cap — bounds spam without dropping the connection.
    if conn_fails.load(Ordering::Relaxed) >= max_auth_fails {
        respond(&mut stream, StatusCode::UNAUTHORIZED).await?;
        return stream.finish().await.map_err(Into::into);
    }

    // Escalating per-IP backoff before the attempt, then a hard deadline.
    tokio::time::sleep(limiter.backoff(ip)).await;
    let authorization = req
        .headers()
        .get(quish_proto::HEADER_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    // A challenge follow-up round echoes its opaque token + responses here.
    let answer = req
        .headers()
        .get(quish_proto::HEADER_CHALLENGE_RESPONSE)
        .and_then(|v| v.to_str().ok())
        .and_then(quish_proto::decode_challenge_answer);
    let outcome = timeout(
        AUTH_DEADLINE,
        backend.authenticate(conn_id, authorization, answer.as_ref(), &conn_info),
    )
    .await
    .unwrap_or(AuthOutcome::Deny);

    match outcome {
        AuthOutcome::Deny => {
            limiter.record_failure(ip);
            conn_fails.fetch_add(1, Ordering::Relaxed);
            info!(%conn_id, peer = %conn_info.peer_addr, "auth failed");
            respond(&mut stream, StatusCode::UNAUTHORIZED).await?;
            stream.finish().await.map_err(Into::into)
        }
        AuthOutcome::Challenge(challenge) => {
            // Not a failure: leave conn_fails/limiter untouched. Reply 401 + the
            // challenge header and finish this stream; the client answers on a
            // fresh CONNECT (challenge state is parked server-side, keyed by
            // conn_id). The conn_fails cap check above still guards terminal
            // failures, and the per-IP backoff already ran before this attempt.
            info!(%conn_id, "auth challenge issued");
            respond_challenge(&mut stream, &challenge).await?;
            stream.finish().await.map_err(Into::into)
        }
        AuthOutcome::Allow => {
            limiter.record_success(ip);
            info!(%conn_id, "quish session authenticated");
            respond(&mut stream, StatusCode::OK).await?;
            backend.serve(conn_id, stream, allow_forward).await
        }
    }
}

async fn respond(stream: &mut ReqStream, status: StatusCode) -> Result<()> {
    let resp = Response::builder()
        .status(status)
        .body(())
        .expect("valid response");
    stream.send_response(resp).await.context("send response")
}

/// Reply `401` with the challenge header (base64 postcard) so the client knows to
/// run a challenge round rather than treat the `401` as a terminal failure.
async fn respond_challenge(
    stream: &mut ReqStream,
    challenge: &quish_proto::Challenge,
) -> Result<()> {
    let resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            quish_proto::HEADER_CHALLENGE,
            quish_proto::encode_challenge(challenge),
        )
        .body(())
        .expect("valid response");
    stream.send_response(resp).await.context("send challenge")
}
