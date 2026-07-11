//! Worker-side rustls signing proxy. The host private key lives only in the
//! monitor; the worker's cert resolver hands rustls a [`ProxySigningKey`] whose
//! `sign` forwards the message to the monitor over the (blocking) signing socket
//! and returns the signature. rustls's `Signer::sign` is synchronous, so a
//! dedicated thread owns the socket and a std channel bridges to it.

use std::fmt;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;

use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::ipc::{self, SignRequest, SignResponse};

/// A signing job handed to the socket thread; the reply comes back via `reply`.
struct Job {
    message: Vec<u8>,
    reply: mpsc::Sender<Option<Vec<u8>>>,
}

/// rustls `SigningKey` that proxies to the monitor. Advertises a single scheme
/// (the host key's), decided by the monitor and passed to the worker.
pub struct ProxySigningKey {
    jobs: mpsc::Sender<Job>,
    scheme: SignatureScheme,
    algorithm: SignatureAlgorithm,
}

impl fmt::Debug for ProxySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySigningKey")
            .field("scheme", &self.scheme)
            .finish()
    }
}

impl ProxySigningKey {
    /// `stream` is the worker's end of the signing socket.
    pub fn new(stream: UnixStream, scheme: SignatureScheme) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::spawn(move || {
            let mut stream = stream;
            while let Ok(job) = rx.recv() {
                let sig = sign_once(&mut stream, &job.message);
                let _ = job.reply.send(sig);
            }
        });
        Self {
            jobs: tx,
            scheme,
            algorithm: algorithm_of(scheme),
        }
    }
}

fn sign_once(stream: &mut UnixStream, message: &[u8]) -> Option<Vec<u8>> {
    ipc::sign_write(
        stream,
        &SignRequest {
            message: message.to_vec(),
        },
    )
    .ok()?;
    match ipc::sign_read::<SignResponse>(stream).ok()?? {
        SignResponse::Signature(sig) => Some(sig),
        SignResponse::Failed => None,
    }
}

impl SigningKey for ProxySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.scheme).then(|| {
            Box::new(ProxySigner {
                jobs: self.jobs.clone(),
                scheme: self.scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

struct ProxySigner {
    jobs: mpsc::Sender<Job>,
    scheme: SignatureScheme,
}

impl fmt::Debug for ProxySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySigner").finish()
    }
}

impl Signer for ProxySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let (tx, rx) = mpsc::channel();
        self.jobs
            .send(Job {
                message: message.to_vec(),
                reply: tx,
            })
            .map_err(|_| rustls::Error::General("signing thread gone".into()))?;
        match rx.recv() {
            Ok(Some(sig)) => Ok(sig),
            _ => Err(rustls::Error::General("monitor signing failed".into())),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Map a signature scheme to its algorithm (only the schemes we might advertise).
fn algorithm_of(scheme: SignatureScheme) -> SignatureAlgorithm {
    match u16::from(scheme) {
        0x0807 => SignatureAlgorithm::ED25519,
        0x0403 | 0x0503 | 0x0603 => SignatureAlgorithm::ECDSA,
        _ => SignatureAlgorithm::RSA,
    }
}
