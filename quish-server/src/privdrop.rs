//! Privilege-drop helpers (all via nix's safe wrappers — no `unsafe`).
//!
//! Two callers: the **worker** drops to the fixed unprivileged `quish` user inside
//! a chroot; the **session helper** (`--internal-run-session`) drops to the
//! *authenticated* user and execs their shell.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

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

    // Die with the monitor: if the root parent goes away, the kernel SIGKILLs us
    // so an orphaned worker can't linger holding the port. Must be set *after*
    // the credential change (setuid clears PR_SET_PDEATHSIG).
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL).context("set_pdeathsig")?;

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
    // Transfer channels branch off before any tty/exec setup: the helper opens
    // the requested file AS the user and streams it, never execing a shell.
    if let Ok(path) = std::env::var(ipc::ENV_SESS_TRANSFER_PATH) {
        return run_transfer_helper(path);
    }
    if let Ok(path) = std::env::var(ipc::ENV_SESS_TRANSFER_WRITE_PATH) {
        return run_transfer_write_helper(path);
    }
    if let Ok(path) = std::env::var(ipc::ENV_SESS_MKDIR_PATH) {
        return run_mkdir_helper(path);
    }
    let uid = Uid::from_raw(ipc::env_u32(ipc::ENV_SESS_UID)?);
    let gid = Gid::from_raw(ipc::env_u32(ipc::ENV_SESS_GID)?);
    let user = ipc::env(ipc::ENV_SESS_USER)?;
    let home = ipc::env(ipc::ENV_SESS_HOME)?;
    let shell = ipc::env(ipc::ENV_SESS_SHELL)?;
    let term = std::env::var(ipc::ENV_SESS_TERM).unwrap_or_else(|_| "xterm".into());
    let command = std::env::var(ipc::ENV_SESS_COMMAND).ok();

    // Exec channels have no controlling TTY, but still become a session/group
    // leader so the monitor can signal the whole command group (see plan 009).
    // Shell channels setsid() inside the tty branch below; don't double-setsid.
    if command.is_some() && std::env::var(ipc::ENV_SESS_TTY).is_err() {
        nix::unistd::setsid().context("setsid (exec)")?;
    }

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

/// Transfer-channel entry: drop to the target user, then open `path` and copy it
/// to stdout (the pipe the monitor handed the worker). The credential drop
/// happens BEFORE open() — identical ordering to the shell/exec path — so the
/// kernel enforces the *user's* permissions on the open, never root's or the
/// worker's. Only regular files are served (fstat refuses devices/FIFOs/etc.).
fn run_transfer_helper(path: String) -> Result<()> {
    let uid = Uid::from_raw(ipc::env_u32(ipc::ENV_SESS_UID)?);
    let gid = Gid::from_raw(ipc::env_u32(ipc::ENV_SESS_GID)?);
    let user = ipc::env(ipc::ENV_SESS_USER)?;

    // Identity boundary (reuse the shell/exec ordering verbatim): supplementary
    // groups, then gid, then uid last while still privileged.
    let cuser = CString::new(user).context("user cstring")?;
    initgroups(&cuser, gid).context("initgroups")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;
    if let Ok(home) = ipc::env(ipc::ENV_SESS_HOME) {
        let _ = chdir(home.as_str());
    }

    // O_NONBLOCK so opening a FIFO/device/socket can't hang the helper; it is a
    // no-op on regular files. We fstat the opened fd and serve ONLY regular
    // files — everything else exits nonzero (→ terminal ExitStatus).
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(&path)
        .with_context(|| format!("open {path}"))?;
    let meta = file.metadata().context("fstat")?;
    if !meta.file_type().is_file() {
        bail!("refusing non-regular file: {path}");
    }

    let mut stdout = std::io::stdout().lock();
    std::io::copy(&mut file, &mut stdout).context("copy file to stdout")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

/// Upload-channel entry: drop to the target user, then create/open `path` for
/// writing and copy stdin (the pipe the monitor handed the worker) into it. The
/// credential drop happens BEFORE open() — identical ordering to download — so
/// the kernel enforces the *user's* permissions on the create/write, never
/// root's or the worker's. Only regular files are written (fstat refuses
/// devices/FIFOs/etc.). O_TRUNC means a partial write on error leaves a
/// truncated file — acceptable, matches `cat > file`.
fn run_transfer_write_helper(path: String) -> Result<()> {
    let uid = Uid::from_raw(ipc::env_u32(ipc::ENV_SESS_UID)?);
    let gid = Gid::from_raw(ipc::env_u32(ipc::ENV_SESS_GID)?);
    let user = ipc::env(ipc::ENV_SESS_USER)?;
    let mode = ipc::env_u32(ipc::ENV_SESS_TRANSFER_MODE)?;

    // Identity boundary (reuse the shell/exec/download ordering verbatim).
    let cuser = CString::new(user).context("user cstring")?;
    initgroups(&cuser, gid).context("initgroups")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;
    if let Ok(home) = ipc::env(ipc::ENV_SESS_HOME) {
        let _ = chdir(home.as_str());
    }

    // O_NONBLOCK so opening an existing FIFO/device can't hang; no-op on a
    // regular file. fstat and refuse anything but a regular file.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(&path)
        .with_context(|| format!("open {path}"))?;
    let meta = file.metadata().context("fstat")?;
    if !meta.file_type().is_file() {
        bail!("refusing non-regular file: {path}");
    }

    let mut stdin = std::io::stdin().lock();
    std::io::copy(&mut stdin, &mut file).context("copy stdin to file")?;
    file.flush().context("flush file")?;
    Ok(())
}

/// Mkdir-channel entry: drop to the target user, then create `path` (one
/// level; the client creates parents first). The credential drop happens
/// BEFORE mkdir() — identical ordering to the other helper modes — so the
/// kernel enforces the *user's* permissions. An existing directory at `path`
/// is success (idempotent re-upload); anything else is a nonzero exit.
fn run_mkdir_helper(path: String) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let uid = Uid::from_raw(ipc::env_u32(ipc::ENV_SESS_UID)?);
    let gid = Gid::from_raw(ipc::env_u32(ipc::ENV_SESS_GID)?);
    let user = ipc::env(ipc::ENV_SESS_USER)?;
    let mode = ipc::env_u32(ipc::ENV_SESS_TRANSFER_MODE)?;

    // Identity boundary (reuse the shell/exec/transfer ordering verbatim).
    let cuser = CString::new(user).context("user cstring")?;
    initgroups(&cuser, gid).context("initgroups")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;
    if let Ok(home) = ipc::env(ipc::ENV_SESS_HOME) {
        let _ = chdir(home.as_str());
    }

    match std::fs::DirBuilder::new().mode(mode).create(&path) {
        Ok(()) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                && std::fs::metadata(&path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false) =>
        {
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("mkdir {path}")),
    }
}
