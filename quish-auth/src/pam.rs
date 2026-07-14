//! PAM password backend. Runs in the monitor (needs root); service name `quish`
//! (see `dist/pam.d/quish`). The blocking PAM C calls run on a `spawn_blocking`
//! thread so they never stall the async runtime.

use pam_client::{Context, Flag, conv_mock::Conversation};
use zeroize::Zeroizing;

use crate::{AuthBackend, ConnInfo, Credentials, Verdict};

/// PAM service name; maps to `/etc/pam.d/quish`.
const SERVICE: &str = "quish";

/// Authenticates `Password` credentials against PAM.
#[derive(Debug, Default)]
pub struct PamBackend;

#[async_trait::async_trait]
impl AuthBackend for PamBackend {
    fn name(&self) -> &'static str {
        "pam"
    }

    fn supports(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Password { .. })
    }

    async fn authenticate(&self, _conn: &ConnInfo, creds: &Credentials) -> Verdict {
        let Credentials::Password { username, password } = creds else {
            return Verdict::Deny;
        };
        let username = username.clone();
        let password = Zeroizing::new(password.to_string());

        // PAM is blocking C; keep it off the reactor.
        let ok = tokio::task::spawn_blocking(move || {
            let mut ctx = match Context::new(
                SERVICE,
                None,
                // Borrow the inner String for the C conversation; `password`
                // (Zeroizing) is moved into the closure and wiped when it drops
                // at closure end. pam_client takes an owned copy it may not
                // scrub — residual outside our control.
                Conversation::with_credentials(username.clone(), &*password),
            ) {
                Ok(c) => c,
                Err(_) => return false,
            };
            ctx.authenticate(Flag::NONE).is_ok() && ctx.acct_mgmt(Flag::NONE).is_ok()
        })
        .await
        .unwrap_or(false);

        if ok {
            // PAM authenticated the name we passed in.
            match creds {
                Credentials::Password { username, .. } => Verdict::Allow {
                    user: username.clone(),
                },
                _ => unreachable!(),
            }
        } else {
            Verdict::Deny
        }
    }
}

/// An open PAM login session, held for the lifetime of a spawned session
/// (Q1 = option B: a fresh `Context` per session, no re-authentication).
///
/// Created at spawn time by [`open_session`] for an already-authenticated user,
/// it runs the account + session + credential stack (`acct_mgmt` +
/// `open_session`, which itself does `setcred(ESTABLISH)` → `pam_open_session` →
/// `setcred(REINITIALIZE)`) and captures the resulting PAM environment. The
/// session is kept open across RPCs by `leak()`ing the borrowed `Session` back
/// into a resumable [`SessionToken`] and owning the `Context` here; `Drop`
/// resumes it with `unleak_session` and closes it (`pam_close_session` +
/// `setcred(DELETE_CRED)`). `Context<ConvT>` is `Send` when `ConvT: Send`
/// (`conv_null::Conversation` is an empty `Send` struct), so the guard can live
/// in the monitor's per-connection `State`.
///
/// The whole type is behind `#[cfg(feature = "pam")]` (the `pam` module is
/// feature-gated in `lib.rs`); the no-PAM build never sees it.
pub struct PamSession {
    // Field order matters for drop: `token` is consumed via `ctx` in `Drop`, so
    // both must outlive it; Rust drops fields top-to-bottom but our `Drop` impl
    // runs first and uses both, so ordering here is not load-bearing.
    ctx: Context<pam_client::conv_null::Conversation>,
    token: pam_client::SessionToken,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

impl PamSession {
    /// The PAM environment (`pam_getenvlist`) captured after `open_session`.
    /// Propagated to the session helper so `pam_env`/`pam_systemd`-style vars
    /// (`XDG_RUNTIME_DIR`, …) reach the login shell.
    pub fn env(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.env
    }
}

impl Drop for PamSession {
    fn drop(&mut self) {
        // Resume the leaked session on the owning context and drop it: that runs
        // `pam_close_session` + `pam_setcred(DELETE_CRED)` (pam-client
        // session.rs Drop). Balanced against the `open_session` below.
        let session = self.ctx.unleak_session(self.token);
        drop(session);
    }
}

impl std::fmt::Debug for PamSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PamSession")
            .field("env_vars", &self.env.len())
            .finish_non_exhaustive()
    }
}

/// Open a PAM login session for an already-authenticated `username`, returning a
/// guard that closes it on drop.
///
/// Runs a **no-authentication** pass with a null conversation: `acct_mgmt`
/// (account stage) + `open_session` (session + credential stages). This is only
/// ever called *after* a verdict is `Allow`, so it never shapes an auth failure
/// and never runs before a successful auth. Blocking PAM C calls — the caller
/// (the monitor) invokes this inline in its control loop like `spawn_shell`.
///
/// Works for both password and pubkey logins (Q2 = option A): the account +
/// session pass is driven purely by username, independent of how the user
/// authenticated.
pub fn open_session(username: &str) -> anyhow::Result<PamSession> {
    use anyhow::Context as _;
    let mut ctx = Context::new(
        SERVICE,
        Some(username),
        pam_client::conv_null::Conversation::new(),
    )
    .map_err(|e| anyhow::anyhow!("pam ctx for session: {e}"))?;
    ctx.acct_mgmt(Flag::NONE)
        .map_err(|e| anyhow::anyhow!("pam acct_mgmt (session): {e}"))?;
    let session = ctx
        .open_session(Flag::NONE)
        .map_err(|e| anyhow::anyhow!("pam open_session: {e}"))
        .context("opening PAM session")?;
    // Capture the PAM env before leaking (needs the live `Session`); then leak
    // to release the `&mut Context` borrow so `ctx` can move into the guard.
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = session.envlist().into();
    let token = session.leak();
    Ok(PamSession { ctx, token, env })
}
