# quish

SSH-like remote shell over **HTTP/3**. Leans on QUIC/TLS 1.3 for transport crypto,
key exchange, and stream multiplexing; keeps the pre-auth attack surface small and
privilege-separated. ssh3-*shaped* (draft-michel-ssh3-00) but with our own wire
format — no interop with the reference ssh3 implementation.

Linux only, both sides. Cargo workspace, edition 2024.

Full design + milestones: `~/.claude/plans/plan-a-new-project-gentle-charm.md`.

## Hard invariants (do not violate)

- **`unsafe_code = "deny"` workspace-wide.** Zero `unsafe` in our crates. PAM's C API
  is reached only through the `pam-client` safe wrapper (bindgen lives in the dep).
  No `#[allow(unsafe_code)]` — if a task seems to need one, stop and reconsider.
- **Host private key never enters the worker.** The worker proxies each rustls
  handshake signature to the monitor over the sync signing channel.
- **Monitor owns identity.** Auth verdicts and the `conn_id → AuthedUser` map live in
  the monitor; it never trusts a worker-supplied username at spawn time.
- **Anti-enumeration is centralized in the auth registry, not per-backend.** Every
  failure → identical 401, connection stays up, reply padded to a constant-time floor
  (`sleep_until(started + FAIL_DELAY)`). No backend gets to shape a failure response.
- **Never `select!` directly over a non-cancel-safe frame read.** Use a dedicated
  reader task feeding an mpsc channel. (Regression from old quish.)

## Layout

- `quish-proto` — wire types (`ChannelMessage`, `ChannelOpen`), postcard frame codec +
  size caps, header/status/version consts. Shared, no I/O.
- `quish-auth` — `AuthBackend` trait, `Credentials`, the registry, `pam.rs`, `pubkey.rs`.
  Adding an auth method = new module impl'ing the trait + one registry match arm.
- `quish-server` — `quishd`: `main` (sync, forks pre-tokio), `monitor.rs`, `worker.rs`,
  `session.rs` (PTY/exec), `ratelimit.rs`, `config.rs`.
- `quish-client` — `quish` CLI: `connect.rs` (cert verifier + TOFU pinning), terminal
  raw mode, channel pump.
- `dist/` — `server.toml`, systemd unit, `pam.d/quish` (`pam_unix ... nodelay`),
  `sysusers.d/quishd.conf`.

## Architecture in one paragraph

`quishd` starts root, binds UDP, then **forks before tokio**. The **worker** (child:
chroot to `/run/quishd`, setuid `quish`, `no_new_privs`) runs all quinn/h3/rustls and
untrusted parsing, pre- and post-auth. The **monitor** (root parent) holds the auth
registry (PAM needs root), the host key, and session spawning. They talk over two
`SOCK_SEQPACKET` socketpairs (async postcard RPC + sync signing); PTY/exec fds pass to
the worker via `SCM_RIGHTS`. A fully compromised worker still can't read the host key,
forge an identity, or setuid.

Session setup is an H3 Extended CONNECT (`:protocol = quish`) on the configured secret
`path` (default `/quish`; any other path → generic 404 before quish logic). Auth rides
the `Authorization` header: Basic → PAM password, Bearer → signed-token pubkey (OpenSSH
ed25519, `~/.config/quish/authorized_keys`, channel-bound via TLS keying-material export
+ timestamp). Each further channel (shell, exec) is its own Extended CONNECT on the same
authed connection. Server identity: web PKI if the cert validates, else TOFU pinning
(`~/.config/quish/known_hosts`, hard-fail on mismatch).

## Workflow (mandated)

- **Add deps only via `cargo add`** — never hand-edit `Cargo.toml` versions.
- Hardening passes / pre-release: `cargo +nightly udeps`, `cargo outdated`,
  `cargo audit`, `cargo deny`.
- Lints gate from commit one: `cargo fmt`, `cargo clippy -- -D warnings`.
- **Testing uses podman** (not docker) — needed for root + real PAM + PTY e2e.
- Dev-mode e2e without root: server `--dev-insecure-user <name>` (any password, no
  privdrop, single process); client reads `QUISH_PASSWORD` for non-interactive runs.

## Stack

tokio, quinn, h3 (0.0.8, `enable_extended_connect`), h3-quinn, rustls, rustls-pki-types,
rcgen, postcard, serde, ssh-key, pam-client, async-trait, nix, clap, toml, tracing,
zeroize, rpassword.

## Git

Merge fast-forward only (`git merge --ff-only`); never create merge commits.

## v1 scope

Interactive PTY shell + remote command exec. Deferred (protocol leaves room):
`-L`/`-R` forwarding, file transfer, OIDC bearer auth, multi-round/challenge auth,
seccomp on the worker, non-ed25519 keys.
