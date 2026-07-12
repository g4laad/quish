//! Client QUIC endpoint + server-identity verification.
//!
//! Identity policy: try the web PKI first (a real cert on a real hostname just
//! works, no ceremony). On failure, fall back to SSH-style trust-on-first-use —
//! prompt the user before pinning the cert's SHA-256 in
//! `~/.config/quish/known_hosts`, then hard-fail on any later mismatch. This is
//! `StrictHostKeyChecking=ask` semantics.

use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::WebPkiServerVerifier,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Build a client endpoint that verifies the server via web PKI → TOFU pinning.
/// `host_key` is the `host:port` string the fingerprint is pinned under.
pub fn endpoint(host_key: String) -> Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("building web PKI verifier")?;

    let verifier = Arc::new(TofuVerifier {
        webpki,
        provider: rustls::crypto::ring::default_provider().into(),
        host_key,
        known_hosts: known_hosts_path()?,
    });
    let verifier: Arc<dyn ServerCertVerifier> = verifier;

    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![quish_proto::ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("quinn rustls client config")?;

    // Keep-alive under the server's idle timeout so an idle interactive shell
    // (no keystrokes) isn't reaped as a dead connection.
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().unwrap()).context("binding client endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn known_hosts_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".config/quish/known_hosts"))
}

#[derive(Debug)]
struct TofuVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    host_key: String,
    known_hosts: PathBuf,
}

// Serializes known_hosts read+pin so a first connect can't race itself.
// (Realistically one target per process, so contention is nil.)
static LOCK: Mutex<()> = Mutex::new(());

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1. Web PKI: if the cert chains to a system root, trust it outright.
        if self
            .webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            .is_ok()
        {
            return Ok(ServerCertVerified::assertion());
        }

        // 2. TOFU: pin the end-entity fingerprint.
        let fp = quish_proto::cert_fingerprint(end_entity);
        let _guard = LOCK.lock().unwrap();
        match lookup(&self.known_hosts, &self.host_key) {
            Some(pinned) if pinned == fp => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(format!(
                "host key mismatch for {h} — possible MITM; refusing to connect. \
                 If you know the server key changed, run: quish known-hosts remove {h}",
                h = self.host_key
            ))),
            None => {
                if !prompt_accept(&self.host_key, &fp) {
                    return Err(rustls::Error::General(format!(
                        "host key verification failed for {} (not accepted)",
                        self.host_key
                    )));
                }
                pin(&self.known_hosts, &self.host_key, &fp)
                    .map_err(|e| rustls::Error::General(format!("pinning host key: {e}")))?;
                eprintln!(
                    "quish: pinned new host key for {} (SHA-256 {fp})",
                    self.host_key
                );
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Ask on the controlling terminal whether to trust an unknown host key
/// (ssh `StrictHostKeyChecking=ask`). Reads `/dev/tty` directly so piped stdin is
/// left intact, and refuses (never auto-accepts) when no terminal is available.
fn prompt_accept(host: &str, fp: &str) -> bool {
    let (Ok(w), Ok(r)) = (
        fs::OpenOptions::new().write(true).open("/dev/tty"),
        fs::File::open("/dev/tty"),
    ) else {
        eprintln!(
            "quish: host key for {host} is unknown and no terminal is available \
             to confirm it; refusing to connect"
        );
        return false;
    };
    decide(std::io::BufReader::new(r), w, host, fp)
}

/// Interactive accept / abort / show-fingerprint loop, split from the terminal
/// I/O so it can be driven by tests. `yes` accepts and pins, `no` aborts,
/// `fingerprint` prints the SHA-256 and re-asks; EOF or a read error aborts.
fn decide(mut reader: impl std::io::BufRead, mut w: impl Write, host: &str, fp: &str) -> bool {
    let _ = writeln!(
        w,
        "The authenticity of host '{host}' can't be established.\n\
         It has no entry in your known_hosts file."
    );
    let mut line = String::new();
    loop {
        let _ = write!(w, "Accept host key (yes/no/fingerprint)? ");
        let _ = w.flush();
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = writeln!(w, "\nHost key verification aborted.");
                return false;
            }
            Ok(_) => {}
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "yes" | "y" => return true,
            "no" | "n" => {
                let _ = writeln!(w, "Host key verification aborted.");
                return false;
            }
            "fingerprint" | "fp" | "f" => {
                let _ = writeln!(w, "SHA-256 fingerprint: {fp}");
            }
            _ => {
                let _ = writeln!(w, "Please type 'yes', 'no', or 'fingerprint'.");
            }
        }
    }
}

/// Look up the pinned fingerprint for `host` in a `known_hosts` file.
fn lookup(path: &PathBuf, host: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let (h, fp) = line.split_once(' ')?;
        (h == host).then(|| fp.trim().to_string())
    })
}

/// Append a `host fingerprint` line, creating the file and parents as needed.
fn pin(path: &PathBuf, host: &str, fp: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{host} {fp}")?;
    Ok(())
}

/// Print every pinned `host fingerprint` line to stdout. Missing file = empty.
pub fn list_known_hosts() -> anyhow::Result<()> {
    let path = known_hosts_path()?;
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            for line in contents.lines().filter(|l| !l.trim().is_empty()) {
                println!("{line}");
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("quish: no known_hosts file at {}", path.display());
            Ok(())
        }
        Err(e) => Err(e).context("reading known_hosts"),
    }
}

/// Remove all pins for `host` (exact `host:port` match). Rewrites the file
/// atomically-ish (write a temp, rename). Reports how many were removed.
pub fn remove_known_host(host: &str) -> anyhow::Result<()> {
    let path = known_hosts_path()?;
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("quish: no known_hosts file at {}", path.display());
            return Ok(());
        }
        Err(e) => return Err(e).context("reading known_hosts"),
    };
    let (body, removed) = remove_host_lines(&contents, host);
    if removed == 0 {
        eprintln!("quish: no pinned key for {host}");
        return Ok(());
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &body).context("writing known_hosts")?;
    std::fs::rename(&tmp, &path).context("replacing known_hosts")?;
    eprintln!("quish: removed {removed} pin(s) for {host}");
    Ok(())
}

/// Pure core of `remove_known_host`: drop every line whose first space-delimited
/// token equals `host`, preserving all others. Returns the new file body (with a
/// trailing newline iff non-empty) and the count removed. Unit-tested directly.
fn remove_host_lines(contents: &str, host: &str) -> (String, usize) {
    let mut removed = 0usize;
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let is_match = line
                .split_once(' ')
                .map(|(h, _)| h == host)
                .unwrap_or(false);
            if is_match {
                removed += 1;
            }
            !is_match
        })
        .collect();
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    (body, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_then_lookup_roundtrips() {
        let dir = std::env::temp_dir().join(format!("quish-kh-{}", std::process::id()));
        let path = dir.join("known_hosts");
        let _ = fs::remove_file(&path);
        assert_eq!(lookup(&path, "h:1"), None);
        pin(&path, "h:1", "deadbeef").unwrap();
        assert_eq!(lookup(&path, "h:1"), Some("deadbeef".into()));
        assert_eq!(lookup(&path, "other:1"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_existing_host_drops_it() {
        let contents = "a:1 aa\nb:2 bb\nc:3 cc\n";
        let (body, removed) = remove_host_lines(contents, "b:2");
        assert_eq!(removed, 1);
        assert_eq!(body, "a:1 aa\nc:3 cc\n");
    }

    #[test]
    fn remove_host_with_two_pins_removes_both() {
        let contents = "a:1 aa\nb:2 bb\na:1 dd\n";
        let (body, removed) = remove_host_lines(contents, "a:1");
        assert_eq!(removed, 2);
        assert_eq!(body, "b:2 bb\n");
    }

    #[test]
    fn remove_absent_host_is_noop() {
        let contents = "a:1 aa\nb:2 bb\n";
        let (body, removed) = remove_host_lines(contents, "z:9");
        assert_eq!(removed, 0);
        assert_eq!(body, "a:1 aa\nb:2 bb\n");
    }

    #[test]
    fn remove_preserves_blank_and_garbage_lines() {
        let contents = "a:1 aa\n\ngarbage-no-space\nb:2 bb\n";
        let (body, removed) = remove_host_lines(contents, "b:2");
        assert_eq!(removed, 1);
        assert_eq!(body, "a:1 aa\n\ngarbage-no-space\n");
    }

    #[test]
    fn remove_matches_exact_host_only() {
        let contents = "1.2.3.4:443 aa\n1.2.3.4:4433 bb\n";
        let (body, removed) = remove_host_lines(contents, "1.2.3.4:443");
        assert_eq!(removed, 1);
        assert_eq!(body, "1.2.3.4:4433 bb\n");
    }

    // Drive `decide` with an in-memory reader/writer, returning its verdict and
    // everything it printed so tests can assert on both.
    fn run_decide(input: &[u8], fp: &str) -> (bool, String) {
        let mut out = Vec::new();
        let accepted = decide(
            std::io::Cursor::new(input.to_vec()),
            &mut out,
            "host:443",
            fp,
        );
        (accepted, String::from_utf8(out).unwrap())
    }

    #[test]
    fn accepts_on_yes_or_y() {
        assert!(run_decide(b"yes\n", "aa:bb:cc").0);
        assert!(run_decide(b"y\n", "aa:bb:cc").0);
    }

    #[test]
    fn aborts_on_no_or_n() {
        assert!(!run_decide(b"no\n", "aa:bb:cc").0);
        assert!(!run_decide(b"n\n", "aa:bb:cc").0);
    }

    #[test]
    fn accepts_after_trimming_and_lowercasing() {
        assert!(run_decide(b"  YES \n", "aa:bb:cc").0);
    }

    #[test]
    fn fingerprint_command_shows_fp_then_re_prompts_and_accepts() {
        let (accepted, out) = run_decide(b"fingerprint\nyes\n", "aa:bb:cc");
        assert!(accepted);
        assert!(out.contains("aa:bb:cc"), "fingerprint not displayed: {out}");
    }

    #[test]
    fn fingerprint_aliases_show_fp() {
        for alias in [&b"f\nno\n"[..], &b"fp\nno\n"[..]] {
            let (accepted, out) = run_decide(alias, "aa:bb:cc");
            assert!(!accepted);
            assert!(out.contains("aa:bb:cc"), "alias did not display fp: {out}");
        }
    }

    #[test]
    fn invalid_answer_re_prompts_without_accepting() {
        let (accepted, out) = run_decide(b"maybe\nno\n", "aa:bb:cc");
        assert!(!accepted);
        assert!(out.contains("Please type"), "no re-prompt hint: {out}");
    }

    #[test]
    fn eof_aborts_without_accepting() {
        assert!(!run_decide(b"", "aa:bb:cc").0);
    }
}
