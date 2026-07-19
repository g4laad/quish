# quish

SSH-like remote shell over **HTTP/3**. Leans on QUIC/TLS 1.3 for transport crypto,
key exchange, and stream multiplexing; keeps the pre-auth attack surface small and
privilege-separated. ssh3-*shaped* (draft-michel-ssh3-00) but with our own wire
format — no interop with the reference ssh3 implementation.

Linux only, both sides. Cargo workspace, edition 2024.

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
- `quish-auth` — `AuthBackend` trait, `Credentials`, the registry, `pam.rs`, `pubkey.rs`,
  `totp.rs` (RFC 6238 second factor). `Verdict` is `Allow`/`Deny`/`Challenge` (multi-round);
  the registry also enforces the `UserPolicy` allow/deny-user filter at the verdict.
  Adding an auth method = new module impl'ing the trait + one registry match arm.
- `quish-server` — `quishd`: `main` (sync mode dispatch), `monitor.rs`, `worker.rs`,
  `session.rs` (dev-mode PTY/exec, file transfer, port-forward pumps), `ipc.rs`
  (control + signing wire types/framing), `privdrop.rs` (chroot/setuid + session
  helper: shell/exec + read/write/mkdir transfer helpers, all post-setuid),
  `signproxy.rs` (rustls signing proxy), `transport.rs` (`Backend` seam +
  challenge store), `ratelimit.rs` (per-IP DoS caps), `config.rs` (TOML file;
  CLI flags override).
- `quish-client` — `quish` CLI: `connect.rs` (cert verifier + TOFU pinning +
  challenge round), `terminal.rs` (raw mode + channel pump), `cp.rs` (scp-style
  `quish cp` up/download). Subcommands: `keygen`, `totp generate`, `known-hosts`.
- `dist/` — `systemd/quishd.service`, `pam.d/quish` (`pam_unix` auth/account +
  `--features pam` session stack), `sysusers.d/quishd.conf`, `server.toml`.

## Architecture in one paragraph

`quishd` starts root and **re-execs a privilege-separated worker** (`nix::fork` is
`unsafe`; `std::process::Command` forks+execs safely and gives the worker a fresh
address space). The **worker** (child: binds UDP as root, then `chroot`s to
`/run/quishd`, `setuid`s to `quish`, sets `no_new_privs`, then installs an
enforcing seccomp-bpf syscall allowlist — `WORKER_SYSCALLS` in `privdrop.rs`,
so adding a worker syscall may need an allowlist edit; `--no-seccomp` disables
it) runs all quinn/h3/rustls
and untrusted parsing, pre- and post-auth. The **monitor** (root parent) holds the
auth registry (PAM needs root), the host key, session spawning, and — with
`--features pam` — the per-login PAM session stack (`open_session`/`setcred`, held
for the session, closed at logout). Auth verdicts also apply the allow/deny-user
authorization policy. They talk over
two `SOCK_SEQPACKET` socketpairs — a control RPC (auth / spawn / reap) and a
dedicated signing channel — both request/response and blocking (run off the reactor
via `spawn_blocking`); session PTY/pipe fds pass to the worker via `SCM_RIGHTS`.
Received fds are used as `RawFd` + blocking reader/writer threads (never wrapped in
an `OwnedFd`, which needs `unsafe`). Sessions themselves are spawned by the monitor
via a `--run-session` re-exec that `setgid`/`initgroups`/`setuid`s to the target
user before exec. A fully compromised worker still can't read the host key, forge an
identity, or setuid.

Session setup is an H3 Extended CONNECT on the configured secret `path` (default
`/quish`; any other path → generic 404 before quish logic). The `:protocol`
pseudo-header is `webtransport` — h3 0.0.8's `Protocol` is a closed enum, so a custom
`quish` value is impossible without forking; the secret path + `quish-version` header
are the real quish discriminators. Channel frames tunnel over H3 DATA on the CONNECT
stream (not raw QUIC streams). Auth rides
the `Authorization` header: Basic → PAM password, Bearer → signed-token pubkey (OpenSSH
ed25519, `~/.config/quish/authorized_keys`, channel-bound via TLS keying-material export
+ timestamp). An optional TOTP (RFC 6238) second factor runs as a challenge round: the
first CONNECT `401`s with an opaque `quish-challenge` header, the client answers on a
second CONNECT (`Verdict::Challenge`, connection-bound state, single-use, floored to
`FAIL_DELAY` like any failure). Each further channel — shell, exec, file transfer
(`ReadFile`/`WriteFile`/`MkDir`), `-L`/`-R` port forwarding — is its own Extended
CONNECT on the same authed connection. Server identity: web PKI if the cert validates,
else TOFU pinning (`~/.config/quish/known_hosts`, hard-fail on mismatch).

## Workflow (mandated)

- **Add deps only via `cargo add`** — never hand-edit `Cargo.toml` versions.
- Hardening passes / pre-release: `cargo +nightly udeps`, `cargo outdated`,
  `cargo audit`, `cargo deny`.
- Lints gate from commit one: `cargo fmt`, `cargo clippy -- -D warnings`.
- **Testing uses podman** (not docker) — needed for root + real PAM + PTY e2e.
- Dev-mode e2e without root: server `--dev-insecure-user <name>` (any password, no
  privdrop, single process); client reads `QUISH_PASSWORD` for non-interactive runs.
- **`quish-auth`'s `pam` feature is off by default** (only the monitor links PAM).
  Default builds/clippy/tests need no C toolchain. Building `--features pam` on this
  host needs bindgen hints (libclang ships as `libclang-21.so.21`, no clang headers):
  `LIBCLANG_PATH=~/.local/libclang` (a `libclang.so` symlink) +
  `BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/15/include`. Podman/CI
  install `clang`/`libclang-dev` instead and need neither.

## Stack

tokio, quinn, h3 (0.0.8, `enable_extended_connect`), h3-quinn, rustls, rustls-pki-types,
rcgen, postcard, serde, bytes, base64, ssh-key, ed25519-dalek, pam-client, hmac, sha1,
sha2, base32, qrcode, seccompiler, async-trait, nix, rustix, libc, tokio-seqpacket,
portable-pty, clap, toml, tracing, zeroize, rpassword.

## Git

Merge fast-forward only (`git merge --ff-only`); never create merge commits.

## v1 scope

Delivered: interactive PTY shell + remote command exec; scp-style file transfer
(`quish cp` up/download, recursive folders); local (`-L`) and remote (`-R`)
loopback-only port forwarding (both off by default); pubkey (ed25519) + PAM-password
auth with an optional TOTP second factor; PAM session lifecycle; server-side
allow/deny-user authorization; worker seccomp-bpf sandbox; client credential tooling
(`quish keygen`, `quish totp generate`, `quish known-hosts`).

Deferred (protocol leaves room): OIDC bearer auth, non-ed25519 keys, a client config
file (host aliases / per-host defaults).
