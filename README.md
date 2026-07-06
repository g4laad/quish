# quish

An SSH-like remote shell that runs over **HTTP/3**. quish leans on QUIC + TLS 1.3
for transport encryption, key exchange, and stream multiplexing, and keeps a small,
privilege-separated pre-auth attack surface. It is *shaped* like the ssh3 draft
(draft-michel-ssh3-00) but uses its own wire format — no interop with the reference
ssh3 implementation. Linux only, both sides.

> Status: v1 feature-complete (interactive PTY shell + remote exec). Not yet
> audited; run it behind something you trust.

## How it works

A session is an HTTP/3 **Extended CONNECT** to a configurable secret path (default
`/quish`; any other path returns a generic 404 before any quish logic runs).
Credentials ride the `Authorization` header — Basic for a PAM password, Bearer for
a signed, channel-bound public-key token. Each shell/exec channel is its own
Extended CONNECT on the authenticated connection; channel frames tunnel over H3
DATA (length-prefixed postcard, 64 KiB cap).

### Privilege separation

`quishd` starts as root and **re-execs** an unprivileged worker (`std::process`
fork+exec — `nix::fork` is `unsafe`, which the workspace forbids):

- **worker** — binds UDP, then `chroot`s, `setuid`s to `quish`, and sets
  `no_new_privs`. Runs all quinn/h3/rustls and untrusted parsing. Never holds the
  host key; asks the monitor to authenticate and to spawn sessions.
- **monitor** (root) — owns the host private key (signs TLS handshakes on the
  worker's behalf, so the key never enters the worker), the auth registry (PAM +
  pubkey), and session spawning (setuids each session to its authenticated user).

A fully compromised worker still can't read the host key, forge an identity, or
`setuid`. See `CLAUDE.md` for the full design.

## Build

```sh
cargo build --release                       # dev mode only (no PAM)
cargo build --release --features pam -p quish-server   # + PAM (needs clang + libpam-dev)
```

`--features pam` needs `clang`/`libclang-dev` and `libpam0g-dev` (bindgen).

## Run

**Dev mode** (single process, no root, any password for one user — for local e2e):

```sh
quishd --listen 127.0.0.1:4433 --dev-insecure-user "$USER"
QUISH_PASSWORD=x quish "$USER@127.0.0.1:4433" 'echo hi'   # exec
quish "$USER@127.0.0.1:4433"                              # interactive shell
```

**Privilege-separated** (as root; authenticates against real accounts via PAM):

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin quish
sudo mkdir -p /run/quishd
sudo install -m644 dist/pam.d/quish /etc/pam.d/quish
sudo quishd --listen 127.0.0.1:4433 \
     --privsep-user quish --privsep-dir /run/quishd \
     --host-key /var/lib/quishd/host_key.der    # persist the host key
```

Pass `--host-key <path>` to persist the host identity; without it the key is
ephemeral and clients see a host-key mismatch after every restart.

## Client auth

- **Password** (default): prompted, or `QUISH_PASSWORD` for scripts.
- **Public key**: `quish -i ~/.config/quish/id_ed25519 user@host`. Put the public
  key in the *server-side* `~user/.config/quish/authorized_keys` (deliberately
  separate from `~/.ssh/authorized_keys`). ed25519 only.

Server identity is verified against the web PKI, else pinned trust-on-first-use in
`~/.config/quish/known_hosts` (hard-fail on mismatch).

## Deployment

`dist/` ships a systemd unit, `pam.d/quish` (`pam_unix ... nodelay`), and a
`sysusers.d` entry for the `quish` account.

## Hardening

64 KiB frame cap; per-IP connection cap + exponential auth backoff; per-connection
channel and auth-attempt caps; auth deadline; QUIC idle timeout (with client
keep-alive so idle shells survive); centralized constant-time auth-failure floor
(identical 401 for every failure cause). The frame decoder is fuzzed
(`cargo +nightly fuzz run decode --fuzz-dir quish-proto/fuzz`).

## License

MIT OR Apache-2.0.
