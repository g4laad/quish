//! Worker-side rustls signing proxy. The host private key lives only in the
//! monitor; the worker's cert resolver hands rustls a [`ProxySigningKey`] whose
//! `sign` forwards the message to the monitor over the (blocking) signing socket
//! and returns the signature. rustls's `Signer::sign` is synchronous, so a
//! dedicated thread owns the socket and a std channel bridges to it.

use std::fmt;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::ipc::{self, SignRequest, SignResponse};

/// Upper bound on one host-key signing round-trip to the monitor. The signing
/// proxy runs on the worker's single-threaded reactor; without a bound, a slow
/// or hung monitor would block the reactor (and every live session) forever.
/// The normal round-trip is sub-millisecond, so this only ever fires on a fault.
const SIGN_TIMEOUT: Duration = Duration::from_secs(10);

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
    timeout: Duration,
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
        Self::with_timeout(stream, scheme, SIGN_TIMEOUT)
    }

    pub(crate) fn with_timeout(
        stream: UnixStream,
        scheme: SignatureScheme,
        timeout: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        // Bound the socket read so a hung monitor can't block the signing thread
        // (and, via the reply channel, the reactor) forever.
        let _ = stream.set_read_timeout(Some(timeout));
        std::thread::spawn(move || {
            let mut stream = stream;
            while let Ok(job) = rx.recv() {
                match sign_once(&mut stream, &job.message) {
                    SignOutcome::Signed(sig) => {
                        let _ = job.reply.send(Some(sig));
                    }
                    SignOutcome::Refused => {
                        let _ = job.reply.send(None);
                    }
                    SignOutcome::Broken => {
                        // Stream may be desynced; stop. Future `sign()` calls get
                        // `jobs.send` errors -> a clean "signing thread gone".
                        let _ = job.reply.send(None);
                        return;
                    }
                }
            }
        });
        Self {
            jobs: tx,
            scheme,
            algorithm: algorithm_of(scheme),
            timeout,
        }
    }
}

/// Result of one signing attempt over the monitor socket.
enum SignOutcome {
    /// Monitor returned a signature.
    Signed(Vec<u8>),
    /// Monitor cleanly refused (`SignResponse::Failed`). The channel is still
    /// in sync; keep serving future jobs.
    Refused,
    /// I/O error, timeout, or unexpected EOF. The stream may be desynced, so the
    /// signing thread must stop rather than risk reading a stale reply for the
    /// next job.
    Broken,
}

fn sign_once(stream: &mut UnixStream, message: &[u8]) -> SignOutcome {
    if ipc::sign_write(
        stream,
        &SignRequest {
            message: message.to_vec(),
        },
    )
    .is_err()
    {
        return SignOutcome::Broken;
    }
    match ipc::sign_read::<SignResponse>(stream) {
        Ok(Some(SignResponse::Signature(sig))) => SignOutcome::Signed(sig),
        Ok(Some(SignResponse::Failed)) => SignOutcome::Refused,
        Ok(None) | Err(_) => SignOutcome::Broken,
    }
}

impl SigningKey for ProxySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.scheme).then(|| {
            Box::new(ProxySigner {
                jobs: self.jobs.clone(),
                scheme: self.scheme,
                timeout: self.timeout,
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
    timeout: Duration,
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
        match rx.recv_timeout(self.timeout) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::SignatureScheme;
    use std::time::{Duration, Instant};

    #[test]
    fn sign_returns_signature_on_monitor_reply() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // Fake monitor: read the request, reply with a fixed signature.
        let monitor = std::thread::spawn(move || {
            let mut s = theirs;
            let _req = ipc::sign_read::<SignRequest>(&mut s).unwrap().unwrap();
            ipc::sign_write(&mut s, &SignResponse::Signature(vec![1, 2, 3, 4])).unwrap();
        });
        let key =
            ProxySigningKey::with_timeout(ours, SignatureScheme::ED25519, Duration::from_secs(5));
        let signer = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("scheme offered");
        assert_eq!(signer.sign(b"hello").unwrap(), vec![1, 2, 3, 4]);
        monitor.join().unwrap();
    }

    #[test]
    fn sign_times_out_when_monitor_never_replies() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        // `_theirs` is held but never answers -> the round-trip must time out
        // instead of blocking forever.
        let key = ProxySigningKey::with_timeout(
            ours,
            SignatureScheme::ED25519,
            Duration::from_millis(150),
        );
        let signer = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("scheme offered");
        let start = Instant::now();
        let err = signer.sign(b"hello").unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "sign should return promptly, not hang"
        );
        assert!(format!("{err}").contains("signing failed"));
    }
}
