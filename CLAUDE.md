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
- `quish-server` — `quishd`: `main` (sync mode dispatch), `monitor.rs`, `worker.rs`,
  `session.rs` (dev-mode PTY/exec), `ipc.rs` (control + signing wire types/framing),
  `privdrop.rs` (chroot/setuid + session helper), `signproxy.rs` (rustls signing
  proxy), `transport.rs` (`Backend` seam). `ratelimit.rs`/`config.rs` land in M6
  (config is CLI flags for now).
- `quish-client` — `quish` CLI: `connect.rs` (cert verifier + TOFU pinning),
  `terminal.rs` (raw mode + channel pump).
- `dist/` — `systemd/quishd.service`, `pam.d/quish` (`pam_unix ... nodelay`),
  `sysusers.d/quishd.conf`. (`server.toml` deferred with `config.rs`.)

## Architecture in one paragraph

`quishd` starts root and **re-execs a privilege-separated worker** (`nix::fork` is
`unsafe`; `std::process::Command` forks+execs safely and gives the worker a fresh
address space). The **worker** (child: binds UDP as root, then `chroot`s to
`/run/quishd`, `setuid`s to `quish`, sets `no_new_privs`) runs all quinn/h3/rustls
and untrusted parsing, pre- and post-auth. The **monitor** (root parent) holds the
auth registry (PAM needs root), the host key, and session spawning. They talk over
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
- **`quish-auth`'s `pam` feature is off by default** (only the monitor links PAM).
  Default builds/clippy/tests need no C toolchain. Building `--features pam` on this
  host needs bindgen hints (libclang ships as `libclang-21.so.21`, no clang headers):
  `LIBCLANG_PATH=~/.local/libclang` (a `libclang.so` symlink) +
  `BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/15/include`. Podman/CI
  install `clang`/`libclang-dev` instead and need neither.

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
