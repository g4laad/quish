//! Privilege-drop helpers (all via nix's safe wrappers — no `unsafe`).
//!
//! Two callers: the **worker** drops to the fixed unprivileged `quish` user inside
//! a chroot; the **session helper** (`--internal-run-session`) drops to the
//! *authenticated* user and execs their shell.

use std::ffi::CString;

use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Uid, User, chdir, chroot, execve, initgroups, setgid, setgroups, setuid};

use crate::ipc;

/// Look up a user's uid/gid/home/shell from the passwd database.
pub fn lookup_user(name: &str) -> Result<User> {
    User::from_name(name)
        .with_context(|| format!("looking up user {name}"))?
        .with_context(|| format!("no such user: {name}"))
}

/// Worker privilege drop: chroot into `chroot_dir`, then irrevocably drop to
/// `username` (fixed unprivileged account) and set `no_new_privs`. Must run while
/// still root, after all root-only setup (binding, socket connect) is done.
pub fn drop_to_worker(chroot_dir: &str, username: &str) -> Result<()> {
    let user = lookup_user(username)?;
    if user.uid.is_root() {
        bail!("refusing to run worker as root user {username}");
    }

    chroot(chroot_dir).with_context(|| format!("chroot {chroot_dir}"))?;
    chdir("/").context("chdir / after chroot")?;

    // Drop groups → gid → uid, in that order (uid last, while still privileged).
    setgroups(&[user.gid]).context("setgroups")?;
    setgid(user.gid).context("setgid")?;
    setuid(user.uid).context("setuid")?;

    nix::sys::prctl::set_no_new_privs().context("set_no_new_privs")?;

    // Sanity: privilege must be unrecoverable.
    if setuid(Uid::from_raw(0)).is_ok() {
        bail!("worker could still regain root — aborting");
    }
    Ok(())
}

/// `--internal-run-session` entry: drop to the target user and exec their shell
/// (login shell, or `shell -c <command>` for exec channels). Never returns on
/// success (the process image is replaced).
pub fn run_session_helper() -> Result<()> {
    let uid = Uid::from_raw(env_u32(ipc::ENV_SESS_UID)?);
    let gid = Gid::from_raw(env_u32(ipc::ENV_SESS_GID)?);
    let user = env_str(ipc::ENV_SESS_USER)?;
    let home = env_str(ipc::ENV_SESS_HOME)?;
    let shell = env_str(ipc::ENV_SESS_SHELL)?;
    let term = std::env::var(ipc::ENV_SESS_TERM).unwrap_or_else(|_| "xterm".into());
    let command = std::env::var(ipc::ENV_SESS_COMMAND).ok();

    // Shell channels: become a session leader and acquire the pty as our
    // controlling terminal (job control, Ctrl-C, …). stdin/out/err are already the
    // slave; opening the pts path as a fresh session leader (no O_NOCTTY) makes it
    // controlling — no `unsafe` ioctl needed.
    if let Ok(tty) = std::env::var(ipc::ENV_SESS_TTY) {
        nix::unistd::setsid().context("setsid")?;
        let ctty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tty)
            .with_context(|| format!("reopen tty {tty}"))?;
        nix::unistd::dup2_stdin(&ctty).context("dup2 stdin")?;
        nix::unistd::dup2_stdout(&ctty).context("dup2 stdout")?;
        nix::unistd::dup2_stderr(&ctty).context("dup2 stderr")?;
    }

    // Full credential drop for the target user (supplementary groups included).
    let cuser = CString::new(user.clone()).context("user cstring")?;
    initgroups(&cuser, gid).context("initgroups")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;
    let _ = chdir(home.as_str());

    let shell_c = CString::new(shell.clone()).context("shell cstring")?;
    let argv: Vec<CString> = match &command {
        Some(cmd) => vec![
            shell_c.clone(),
            CString::new("-c").unwrap(),
            CString::new(cmd.as_str()).context("command cstring")?,
        ],
        // Login shell: argv[0] = "-<basename>" is the classic login convention.
        None => {
            let base = shell.rsplit('/').next().unwrap_or(&shell);
            vec![CString::new(format!("-{base}")).context("argv0")?]
        }
    };

    // Build a clean, login-like environment explicitly (std::env::set_var is
    // `unsafe` in edition 2024; execve takes the env array directly).
    let envp: Vec<CString> = [
        format!("HOME={home}"),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
        format!("SHELL={shell}"),
        format!("TERM={term}"),
        "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
    ]
    .into_iter()
    .map(|s| CString::new(s).expect("env has no nul"))
    .collect();

    execve(&shell_c, &argv, &envp).context("exec shell")?;
    unreachable!("execve returned without error")
}

fn env_str(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env {key}"))
}

fn env_u32(key: &str) -> Result<u32> {
    env_str(key)?.parse().with_context(|| format!("bad {key}"))
}
