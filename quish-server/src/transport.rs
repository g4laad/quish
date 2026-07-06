//! QUIC/HTTP-3 endpoint setup and the accept loop.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quish_auth::{ConnInfo, Registry, Verdict};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Build a dev endpoint with a fresh self-signed cert and serve until cancelled.
pub async fn run(listen: SocketAddr, path: String, registry: Arc<Registry>) -> Result<()> {
    let endpoint = build_endpoint(listen)?;
    info!(%listen, %path, "quishd listening (dev mode)");

    while let Some(incoming) = endpoint.accept().await {
        let path = path.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, path, registry).await {
                warn!(error = %e, "connection ended with error");
            }
        });
    }
    Ok(())
}

fn build_endpoint(listen: SocketAddr) -> Result<quinn::Endpoint> {
    // Dev cert: fresh self-signed for "localhost". The client pins its fingerprint
    // via TOFU (it won't chain to the web PKI), so we print it for known_hosts.
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
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    quinn::Endpoint::server(server_config, listen).context("binding endpoint")
}

async fn handle_connection(
    incoming: quinn::Incoming,
    path: String,
    registry: Arc<Registry>,
) -> Result<()> {
    let conn = incoming.await.context("QUIC handshake")?;
    let peer_addr = conn.remote_address();
    info!(peer = %peer_addr, "connection established");

    // Derive the channel binding once per connection, before the quinn handle is
    // moved into h3. Pubkey tokens are signed over this exact value.
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
                let registry = registry.clone();
                let conn_info = conn_info.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(resolver, path, registry, conn_info).await {
                        warn!(error = %e, "request ended with error");
                    }
                });
            }
            Ok(None) => return Ok(()),
            // A peer closing with H3_NO_ERROR is a normal end of connection.
            Err(e) if e.is_h3_no_error() => return Ok(()),
            Err(e) => return Err(anyhow::anyhow!("h3 accept: {e}")),
        }
    }
}

type ReqStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    path: String,
    registry: Arc<Registry>,
    conn_info: ConnInfo,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolving request")?;

    // A quish request is an Extended CONNECT (method CONNECT + :protocol set) to the
    // secret path. Anything else looks like a boring web server: generic 404.
    let is_quish = req.method() == Method::CONNECT
        && req.extensions().get::<Protocol>().is_some()
        && req.uri().path() == path;
    if !is_quish {
        respond(&mut stream, StatusCode::NOT_FOUND).await?;
        return stream.finish().await.map_err(Into::into);
    }

    // Authenticate the session. The registry owns anti-enumeration: every failure
    // is an identical 401 padded to a constant-time floor. We keep the connection
    // up (just end this stream) so a failure is indistinguishable from any other.
    let authorization = req
        .headers()
        .get(quish_proto::HEADER_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let user = match registry.authenticate(authorization, &conn_info).await {
        Verdict::Allow { user } => user,
        Verdict::Deny => {
            info!(peer = %conn_info.peer_addr, "auth failed");
            respond(&mut stream, StatusCode::UNAUTHORIZED).await?;
            return stream.finish().await.map_err(Into::into);
        }
    };

    // Identity is the *authenticated* user, never a client-supplied header.
    info!(%user, "quish session authenticated");
    respond(&mut stream, StatusCode::OK).await?;

    // The authed CONNECT stream becomes the channel: client sends ChannelOpen,
    // then we run the PTY shell / exec and tunnel frames until it exits.
    crate::session::serve(stream, &user).await
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
