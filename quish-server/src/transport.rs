//! QUIC/HTTP-3 accept loop, shared by dev mode and the privsep worker. Auth and
//! session spawning are abstracted behind [`Backend`] so the same transport
//! drives an in-process registry (dev) or the monitor RPC client (privsep).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quish_auth::{ConnInfo, Registry, Verdict};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::worker::{MonitorClient, serve_channel};

/// How auth + session spawning are satisfied.
pub enum Backend {
    /// Single-process dev mode: in-process registry, local session spawn.
    Dev { registry: Arc<Registry> },
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
        conn: &ConnInfo,
    ) -> bool {
        match self {
            Backend::Dev { registry } => {
                matches!(
                    registry.authenticate(authorization, conn).await,
                    Verdict::Allow { .. }
                )
            }
            Backend::Privsep { client } => {
                let started = Instant::now();
                let allow = client
                    .authenticate(conn_id, authorization, conn)
                    .await
                    .unwrap_or(false);
                if !allow {
                    tokio::time::sleep_until(started + client.fail_delay).await;
                }
                allow
            }
        }
    }

    async fn serve(&self, conn_id: u64, stream: crate::session::FullStream) -> Result<()> {
        match self {
            Backend::Dev { .. } => crate::session::serve(stream).await,
            Backend::Privsep { client } => serve_channel(client, conn_id, stream).await,
        }
    }

    async fn close(&self, conn_id: u64) {
        if let Backend::Privsep { client } = self {
            client.close(conn_id).await;
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

    let fingerprint = hex(&Sha256::digest(&cert_der));
    info!(%fingerprint, "server certificate SHA-256 (pin as: localhost:PORT <fingerprint>)");

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .context("building rustls server config")?;
    tls.alpn_protocols = vec![quish_proto::ALPN.to_vec()];

    let quic = QuicServerConfig::try_from(tls).context("quinn rustls config")?;
    quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic)), listen)
        .context("binding endpoint")
}

/// Serve until the endpoint is closed.
pub async fn run(endpoint: quinn::Endpoint, path: String, backend: Arc<Backend>) -> Result<()> {
    info!(addr = ?endpoint.local_addr().ok(), %path, "quishd listening");

    static NEXT_CONN: AtomicU64 = AtomicU64::new(1);
    while let Some(incoming) = endpoint.accept().await {
        let path = path.clone();
        let backend = backend.clone();
        let conn_id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, path, backend.clone(), conn_id).await {
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
    conn_id: u64,
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
    };

    let mut h3conn = h3::server::builder()
        .enable_extended_connect(true)
        .build::<h3_quinn::Connection, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("h3 handshake")?;

    loop {
        match h3conn.accept().await {
            Ok(Some(resolver)) => {
                let path = path.clone();
                let backend = backend.clone();
                let conn_info = conn_info.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_request(resolver, path, backend, conn_info, conn_id).await
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

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    path: String,
    backend: Arc<Backend>,
    conn_info: ConnInfo,
    conn_id: u64,
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

    let authorization = req
        .headers()
        .get(quish_proto::HEADER_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !backend
        .authenticate(conn_id, authorization, &conn_info)
        .await
    {
        info!(%conn_id, peer = %conn_info.peer_addr, "auth failed");
        respond(&mut stream, StatusCode::UNAUTHORIZED).await?;
        return stream.finish().await.map_err(Into::into);
    }

    info!(%conn_id, "quish session authenticated");
    respond(&mut stream, StatusCode::OK).await?;
    backend.serve(conn_id, stream).await
}

async fn respond(stream: &mut ReqStream, status: StatusCode) -> Result<()> {
    let resp = Response::builder()
        .status(status)
        .body(())
        .expect("valid response");
    stream.send_response(resp).await.context("send response")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
