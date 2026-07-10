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
