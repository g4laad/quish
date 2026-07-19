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
  With `--features pam`, a password shell login also runs the PAM **session**
  stack (`pam_open_session`/`setcred`, held for the session and closed at logout)
  so the login integrates with the host — `pam_limits`, `pam_env`, and utmp/wtmp
  accounting (`last`/`lastlog`); see `dist/pam.d/quish`.

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

Instead of flags you can use a TOML config (`quishd --config /etc/quish/server.toml`,
see `dist/server.toml`); any CLI flag overrides the file. Privileged ports (`<1024`)
work — the worker binds while still root, then drops privileges.

## Client auth

- **Password** (default): prompted, or `QUISH_PASSWORD` for scripts.
- **Public key**: generate an identity with `quish keygen` (writes
  `~/.config/quish/id_ed25519` + `.pub` at mode 0600/0644, refuses to overwrite),
  then install the printed line in the *server-side*
  `~user/.config/quish/authorized_keys` (deliberately separate from
  `~/.ssh/authorized_keys`) and connect with
  `quish -i ~/.config/quish/id_ed25519 user@host`. ed25519 only.

Server identity is verified against the web PKI, else pinned trust-on-first-use in
`~/.config/quish/known_hosts` (hard-fail on mismatch).

### Two-factor (TOTP)

quish can require a second factor — a time-based one-time code (TOTP, RFC 6238,
the standard authenticator-app scheme) — after the password. The login becomes a
two-round HTTP exchange: the first CONNECT returns `401` carrying an opaque,
per-connection challenge; the client collects the code and answers on a second
CONNECT. The client prompts for the code interactively, or reads it from
`QUISH_TOTP` for scripted runs (like `QUISH_PASSWORD` for the first factor):

```sh
QUISH_PASSWORD=… QUISH_TOTP=123456 quish user@host 'echo hi'
```

Enroll with `quish totp generate <user> <host>`: it prints the per-user base32
secret (the same string an authenticator app stores), an `otpauth://` URI, a
scannable QR code, and the current code to cross-check your app. Install the
printed secret at the *server-side* `~user/.config/quish/totp` (mode 0600).
Enable it with the server's `--totp` (privsep, needs `--features pam` for the
password first factor) or, for local e2e, `--dev-insecure-totp-secret <base32>`
in dev mode.

**Anti-enumeration is preserved.** Every login reaching the second-factor backend
gets an identical challenge — a bogus username is challenged exactly like a real
one — and only the *terminal* verdict differs. A wrong second factor, a wrong
password, and a nonexistent user all end in the same generic `401`, padded to the
same constant-time floor (the floor covers both the challenge round and the
terminal denial), so an attacker cannot tell which — if any — account exists.

### OIDC bearer (experimental)

quish can accept a short-lived OIDC **bearer token** (a compact JWT) in place of a
password or key. The client sends it from the `QUISH_OIDC_TOKEN` environment
variable; a `Bearer` value containing a `.` is discriminated as a JWT and routed
to the OIDC backend (dotless bearers stay pubkey tokens, so this never disturbs
key logins):

```sh
QUISH_OIDC_TOKEN="$(get-my-id-token)" quish user@host 'echo hi'
```

The server validates the token against an operator-provisioned **static JWKS
file** — there is deliberately no network I/O; the monitor never fetches keys or
reaches an IdP. Configure it with an `[oidc]` table (config-file only this slice;
no CLI flags):

```toml
[oidc]
issuer = "https://issuer.example"        # required `iss` claim value
audience = "quish"                       # required `aud` claim value
jwks_file = "/etc/quish/jwks.json"       # static JWKS, re-read every attempt
# user_claim = "preferred_username"      # claim mapped to the local user (default)
# max_token_age_secs = 300               # reject tokens older than this by `iat`
```

A validated token maps the `user_claim` (default `preferred_username`) verbatim to
the local login user. Every failure — bad signature, wrong `iss`/`aud`, expired,
stale `iat`, unknown user — returns the same generic, constant-time-floored `401`
as any other bad credential.

**This slice is EdDSA-only** (Ed25519 / OKP keys); RS256 is a recorded follow-up.

**Replay caveat:** an OIDC token is not channel-bound; keep lifetimes short. A
captured token is replayable until it expires, so mint narrow, short-lived tokens
and prefer a small `max_token_age_secs`. Pair OIDC with `allow_users` (see
[Hardening](#hardening)) so an entire IdP tenant cannot log in by default — scope
logins to the accounts you actually intend to grant.

### Root logins

Root is a first-class login: shell, exec, upload, download, and both auth
methods work for `root@host` (covered by the privsep e2e suite). Note that most
distros ship the root *password* locked (`root:!` in `/etc/shadow`), which
makes password auth fail for root — an environment policy, not a quish
restriction. For root logins prefer pubkey auth: put the ed25519 public key in
`/root/.config/quish/authorized_keys`.

## Client configuration

An optional `~/.config/quish/config.toml` gives the flags-only CLI an
`ssh_config`-style equivalent: a `[defaults]` table and per-alias
`[hosts.<alias>]` blocks, so `quish prod` and `quish cp prod:file .` resolve
the same host. Set `QUISH_CONFIG` to point elsewhere. A missing file is fine; a
malformed file (or an unknown key) fails loud, naming the file.

```toml
[defaults]
identity = "~/.config/quish/id_ed25519"   # optional; tilde-expanded

[hosts.prod]                    # "prod" is the alias used on the CLI
host = "prod.example.com"       # required in every [hosts.*] block
port = 4433                     # optional
user = "alice"                  # optional
path = "/quish"                 # optional secret path
identity = "~/.config/quish/id_prod"      # optional; overrides [defaults]
local_forward = ["5432:127.0.0.1:5432"]   # optional; same syntax as -L
remote_forward = []                        # optional; same syntax as -R
```

Precedence: CLI flags beat the host block, which beats `[defaults]`, which
beats the built-in default; forwards append (the block's `-L`/`-R` lists plus
any given on the CLI both apply).

## File transfer

`quish cp` copies files and folders to or from a server, scp-style. Exactly one of
SRC/DST is remote (`[user@]host:path`); a trailing `/` on the destination means
"into that directory", and a local folder source uploads recursively (symlinks are
skipped, never followed). Files are read and written **as the authenticated user** —
the `open()`/`mkdir()` runs in the setuid'd session helper, never as root or the
worker.

```sh
quish cp ./notes.txt user@host:notes.txt        # upload a file
quish cp user@host:/etc/hostname ./hostname     # download a file
quish cp ./project user@host:project/           # upload a folder (recursive)
```

Auth matches a shell login: password (or `QUISH_PASSWORD`), or `-i <key>` for pubkey.

## Port forwarding

Both directions are **off by default** and **loopback-only** — a forward can only
reach or expose `127.0.0.0/8` / `::1`, never a routable address.

- **Local (`-L [bind:]lport:rhost:rport`)** — enabled by the server's
  `--allow-forward` (or `allow_forward = true`). Connections to the client's
  local port tunnel to `rhost:rport` on the server.
- **Remote (`-R [bind:]rport:lhost:lport`)** — enabled by the server's
  `--allow-remote-forward` (or `allow_remote_forward = true`). The server binds a
  loopback listener on `rport` (refusing non-loopback binds and ports `<1024`);
  each inbound connection is tunneled back to the client, which dials
  `lhost:lport`.

```sh
# expose the client's 127.0.0.1:3000 as 127.0.0.1:8080 on the server
quish -R 8080:127.0.0.1:3000 user@host      # server started with --allow-remote-forward
```

## Deployment

`dist/` ships a systemd unit, `pam.d/quish` (`pam_unix` auth/account plus the
`--features pam` session stack: `pam_limits`/`pam_loginuid`/`pam_env`/`pam_lastlog`),
and a `sysusers.d` entry for the `quish` account.

## Hardening

64 KiB frame cap; per-IP connection cap + exponential auth backoff; per-connection
channel and auth-attempt caps; auth deadline; QUIC idle timeout (with client
keep-alive so idle shells survive); centralized constant-time auth-failure floor
(identical 401 for every failure cause). The frame decoder is fuzzed
(`cargo +nightly fuzz run decode --fuzz-dir quish-proto/fuzz`).

Server-side authorization: `allow_users` / `deny_users` (config keys, or the
repeatable `--allow-user` / `--deny-user` flags) scope who may log in, sshd-style.
`deny_users` always wins; a non-empty `allow_users` is an exhaustive allowlist;
both empty means every authenticated user is permitted. The policy is enforced at
the auth verdict, so a rejected user is indistinguishable from a bad credential
(the same generic, constant-time-floored 401 — no policy-specific signal reaches
the client). Both dev and privsep modes.

The network-facing worker is privilege-separated: it binds as root, then
`chroot`s to an empty dir, `setuid`s to the unprivileged `quish` account, and
installs a **seccomp-bpf syscall allowlist** — after that the worker may call
only the ~50 syscalls it legitimately makes (QUIC/TLS/H3 I/O, the tokio reactor,
memory/thread management), so a memory-corruption exploit in the untrusted
parsing can't reach `ptrace`, `execve`, `io_uring`, raw sockets, `openat`, etc.
The filter is enforcing by default (unlisted syscall → the worker is killed and
the connection drops); `--no-seccomp` (or `no_seccomp = true`) is an escape
hatch for a kernel/glibc regression. The host key, auth verdicts, and session
spawning stay in the root monitor, which the filter does not touch.

## License

MIT OR Apache-2.0.
