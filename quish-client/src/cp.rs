//! `quish cp` — scp-style file/folder transfer.
//!
//! Exactly one of SRC/DST is a remote `[user@]host:path` spec; the other is a
//! local path. A remote SRC downloads (into a directory or at a chosen name); a
//! local file SRC uploads; a local directory SRC uploads recursively (creating
//! remote directories as the authenticated user via `MkDir`). Each transfer op
//! opens its own Extended CONNECT channel on the one authed connection.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use quish_proto::{ChannelMessage, ChannelOpen};

#[derive(clap::Args, Debug)]
pub(crate) struct CpArgs {
    /// Source: a local path, or `[user@]host:path` (remote).
    pub(crate) src: String,
    /// Destination: a local path, or `[user@]host:path` (remote).
    /// A trailing '/' means "into that directory".
    pub(crate) dst: String,
    /// OpenSSH ed25519 private key for pubkey auth (else password auth).
    #[arg(short, long)]
    pub(crate) identity: Option<std::path::PathBuf>,
    /// Server UDP port. [default: host block `port`, else 4433]
    #[arg(short = 'P', long)]
    pub(crate) port: Option<u16>,
    /// Secret HTTP/3 connect path. [default: host block `path`, else /quish]
    #[arg(long)]
    pub(crate) connect_path: Option<String>,
}

/// One side of a `quish cp` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpSpec {
    Local(String),
    Remote {
        user: Option<String>,
        host: String,
        path: String,
    },
}

/// scp's rule: a spec is remote iff a `:` appears before the first `/`.
/// `[v6]:path` brackets an IPv6 host; `user@` may prefix the host.
pub(crate) fn parse_cp_spec(s: &str) -> Result<CpSpec> {
    // Candidate `user@` split: the first '@' that comes before the first ':' and
    // before the first '/'. An '@' after either is part of the host/path.
    let first_colon = s.find(':');
    let first_slash = s.find('/');
    let (user, rest) = match s.find('@') {
        Some(at) if first_colon.is_none_or(|c| at < c) && first_slash.is_none_or(|sl| at < sl) => {
            (Some(s[..at].to_string()), &s[at + 1..])
        }
        _ => (None, s),
    };

    if let Some(after_bracket) = rest.strip_prefix('[') {
        // Bracketed IPv6 host: `[host]:path`.
        let close = after_bracket
            .find(']')
            .with_context(|| format!("unterminated '[' in remote spec: {s}"))?;
        let host = &after_bracket[..close];
        if host.is_empty() {
            bail!("empty host in remote spec: {s}");
        }
        let path = after_bracket[close + 1..]
            .strip_prefix(':')
            .with_context(|| format!("expected ':' after ']' in remote spec: {s}"))?;
        return Ok(CpSpec::Remote {
            user,
            host: host.to_string(),
            path: path.to_string(),
        });
    }

    // Non-bracketed: remote iff a ':' occurs before the first '/'.
    match rest.find(':') {
        Some(colon) if !rest[..colon].contains('/') => {
            let host = &rest[..colon];
            if host.is_empty() {
                bail!("empty host in remote spec: {s}");
            }
            Ok(CpSpec::Remote {
                user,
                host: host.to_string(),
                path: rest[colon + 1..].to_string(),
            })
        }
        // No colon, or a '/' before it: the whole original spec is local.
        _ => Ok(CpSpec::Local(s.to_string())),
    }
}

/// Local landing path for a download: `dst` itself, or `dst/<basename of
/// remote>` when dst names an existing dir or ends with '/'. Errors when the
/// remote path has no basename (trailing '/' — directories can't download).
pub(crate) fn resolve_local_dst(
    dst: &str,
    dst_is_dir: bool,
    remote: &str,
) -> Result<std::path::PathBuf> {
    if dst_is_dir || dst.ends_with('/') {
        let base = remote_basename(remote).context("cannot download a directory")?;
        Ok(std::path::Path::new(dst).join(base))
    } else {
        Ok(std::path::PathBuf::from(dst))
    }
}

/// Remote landing path for an upload: `dst` itself, or `dst/<src_name>` when
/// dst is empty, ".", "..", or ends with '/'.
pub(crate) fn resolve_remote_dst(dst: &str, src_name: &str) -> String {
    if dst.is_empty() {
        src_name.to_string()
    } else if dst.ends_with('/') {
        format!("{dst}{src_name}")
    } else if dst == "." || dst == ".." {
        format!("{dst}/{src_name}")
    } else {
        dst.to_string()
    }
}

/// Last path segment of a remote (Unix-style) path, or `None` when empty (the
/// path ends with '/' or is itself empty).
fn remote_basename(remote: &str) -> Option<&str> {
    match remote.rsplit('/').next().unwrap_or("") {
        "" => None,
        base => Some(base),
    }
}

/// Basename of a local source path, with any trailing '/' trimmed first (scp
/// semantics — no rsync "copy contents" rule).
fn local_basename(src: &str) -> String {
    let trimmed = src.trim_end_matches('/');
    std::path::Path::new(trimmed)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| trimmed.to_string())
}

/// The `.<final-name>.quish-part` temp path next to a download destination.
fn part_path(final_path: &std::path::Path) -> std::path::PathBuf {
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let parent = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    parent.join(format!(".{name}.quish-part"))
}

/// Resolve a cp remote spec (`user`/`host` + `--port`) through the config
/// aliases (the same merge matrix as the connect path), and compute the
/// identity chain (`-i` flag → block identity → `[defaults]` identity → none).
/// `--port` is `Option<u16>` so a missing flag lets a host block's `port` win,
/// with 4433 as the final fallback. `--connect-path` is `Option<String>` for the
/// same reason: a missing flag lets a host block's `path` win, with `/quish` as
/// the final fallback (identical to the connect path's `parse_target`).
fn resolve_cp_target(
    user: Option<String>,
    host: String,
    args: &CpArgs,
    cfg: &crate::config::ClientConfig,
) -> Result<(crate::Target, Option<std::path::PathBuf>)> {
    let raw = crate::RawTarget {
        user,
        host,
        port: args.port,
        path: args.connect_path.clone(),
    };
    let resolved = crate::resolve_target(raw, cfg);
    let identity = match args.identity.clone() {
        Some(p) => Some(p),
        None => resolved
            .identity
            .map(|s| crate::config::expand_tilde(&s))
            .transpose()?,
    };
    Ok((resolved.target, identity))
}

/// Entry point from `main()`. Parses both specs, enforces exactly-one-remote
/// (before any network I/O), then downloads / uploads a file / uploads a tree.
/// Returns the process exit code (0, the first nonzero remote status, or 1 for
/// local/transport failures via `Err`).
pub(crate) async fn run_cp(args: CpArgs) -> Result<i32> {
    let src = parse_cp_spec(&args.src)?;
    let dst = parse_cp_spec(&args.dst)?;
    let cfg = crate::config::load()?;

    match (src, dst) {
        (CpSpec::Remote { .. }, CpSpec::Remote { .. }) => {
            bail!("remote-to-remote copy is not supported")
        }
        (CpSpec::Local(_), CpSpec::Local(_)) => bail!("both paths are local; use cp(1)"),
        (
            CpSpec::Remote {
                user,
                host,
                path: remote,
            },
            CpSpec::Local(local),
        ) => {
            let (target, identity) = resolve_cp_target(user, host, &args, &cfg)?;
            let dst_is_dir = std::fs::metadata(&local)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            let final_path = resolve_local_dst(&local, dst_is_dir, &remote)?;
            let (mut send_request, drive, authorization) =
                crate::establish(&target, identity.as_deref()).await?;
            let res = download_one(
                &mut send_request,
                &target,
                &authorization,
                &remote,
                &final_path,
            )
            .await;
            drop(send_request);
            let _ = drive.await;
            res
        }
        (
            CpSpec::Local(local),
            CpSpec::Remote {
                user,
                host,
                path: remote,
            },
        ) => {
            // Local source must exist before any network I/O.
            let meta = std::fs::metadata(&local)
                .with_context(|| format!("cannot access local source {local}"))?;
            let (target, identity) = resolve_cp_target(user, host, &args, &cfg)?;
            if meta.is_dir() {
                let root_mode = meta.permissions().mode() & 0o777;
                let src_name = local_basename(&local);
                let remote_root = resolve_remote_dst(&remote, &src_name);
                // Collect the whole walk before any network op.
                let walk = collect_walk(std::path::Path::new(&local))?;
                let (mut send_request, drive, authorization) =
                    crate::establish(&target, identity.as_deref()).await?;
                let res = upload_tree(
                    &mut send_request,
                    &target,
                    &authorization,
                    std::path::Path::new(&local),
                    &remote_root,
                    root_mode,
                    &walk,
                )
                .await;
                drop(send_request);
                let _ = drive.await;
                res
            } else {
                let src_name = local_basename(&local);
                let remote_final = resolve_remote_dst(&remote, &src_name);
                let (mut send_request, drive, authorization) =
                    crate::establish(&target, identity.as_deref()).await?;
                let res = upload_one(
                    &mut send_request,
                    &target,
                    &authorization,
                    std::path::Path::new(&local),
                    &remote_final,
                )
                .await;
                drop(send_request);
                let _ = drive.await;
                res
            }
        }
    }
}

/// A directory to create and a regular file to upload, both by path relative to
/// the source root (`/`-separated).
struct WalkDir {
    rel: String,
    mode: u32,
}
struct WalkFile {
    rel: String,
}

/// The recursive contents of a source directory: subdirectories (top-down,
/// name-sorted) and regular files. Non-regular entries are skipped here.
struct Walk {
    dirs: Vec<WalkDir>,
    files: Vec<WalkFile>,
}

/// Depth-first walk of `root`, entries sorted by name for a deterministic
/// order. `entry.file_type()` never follows symlinks; non-dir/non-file entries
/// (symlinks, devices, …) are skipped with a warning on stderr.
fn collect_walk(root: &std::path::Path) -> Result<Walk> {
    let mut walk = Walk {
        dirs: Vec::new(),
        files: Vec::new(),
    };
    collect_dir(root, String::new(), &mut walk)?;
    Ok(walk)
}

fn collect_dir(dir: &std::path::Path, rel: String, walk: &mut Walk) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading directory {}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let ft = entry
            .file_type()
            .with_context(|| format!("file type of {}", entry.path().display()))?;
        if ft.is_dir() {
            let mode = entry
                .metadata()
                .with_context(|| format!("metadata of {}", entry.path().display()))?
                .permissions()
                .mode()
                & 0o777;
            walk.dirs.push(WalkDir {
                rel: child_rel.clone(),
                mode,
            });
            collect_dir(&entry.path(), child_rel, walk)?;
        } else if ft.is_file() {
            walk.files.push(WalkFile { rel: child_rel });
        } else {
            eprintln!(
                "quish: skipping non-regular entry {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

/// Download `remote` to `final_path`: write incoming `Data` frames to a temp
/// file `.<name>.quish-part` beside the destination, then rename on
/// `ExitStatus(0)`. A nonzero status, transport error, or a stream that ends
/// with no status deletes the temp file and fails (never a silent success).
async fn download_one(
    send_request: &mut crate::SendRequest,
    target: &crate::Target,
    authorization: &str,
    remote: &str,
    final_path: &std::path::Path,
) -> Result<i32> {
    let (mut send, recv) = crate::open_channel(send_request, target, authorization).await?;
    send.send_data(Bytes::from(quish_proto::encode(&ChannelOpen::ReadFile {
        path: remote.to_string(),
    })?))
    .await
    .context("sending ReadFile open")?;

    let temp_path = part_path(final_path);
    let mut file = std::fs::File::create(&temp_path)
        .with_context(|| format!("creating temp file {}", temp_path.display()))?;

    let mut reader = crate::ChannelFrameReader::new(recv);
    let mut status: Option<i32> = None;
    let mut transport_err: Option<anyhow::Error> = None;
    loop {
        match reader.next().await {
            Ok(Some(ChannelMessage::Data(d))) => {
                if let Err(e) = file.write_all(&d) {
                    transport_err = Some(anyhow::Error::new(e).context("writing download data"));
                    break;
                }
            }
            Ok(Some(ChannelMessage::ExitStatus(c))) => {
                status = Some(c);
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                transport_err = Some(e);
                break;
            }
        }
    }
    let _ = send.finish().await;

    if let Some(e) = transport_err {
        drop(file);
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    match status {
        Some(0) => {
            file.flush().context("flushing download")?;
            drop(file);
            std::fs::rename(&temp_path, final_path)
                .with_context(|| format!("renaming to {}", final_path.display()))?;
            Ok(0)
        }
        Some(code) => {
            drop(file);
            let _ = std::fs::remove_file(&temp_path);
            eprintln!("quish: download of {remote} failed (status {code})");
            Ok(code)
        }
        None => {
            drop(file);
            let _ = std::fs::remove_file(&temp_path);
            bail!("download of {remote} ended without a status");
        }
    }
}

/// Upload the regular file `local` to `remote`, sending its mode (`& 0o777`) in
/// the `WriteFile` open and streaming its bytes as 32 KiB `Data` frames.
async fn upload_one(
    send_request: &mut crate::SendRequest,
    target: &crate::Target,
    authorization: &str,
    local: &std::path::Path,
    remote: &str,
) -> Result<i32> {
    let meta =
        std::fs::metadata(local).with_context(|| format!("cannot access {}", local.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", local.display());
    }
    let mode = meta.permissions().mode() & 0o777;

    let (mut send, recv) = crate::open_channel(send_request, target, authorization).await?;
    send.send_data(Bytes::from(quish_proto::encode(&ChannelOpen::WriteFile {
        path: remote.to_string(),
        mode,
    })?))
    .await
    .context("sending WriteFile open")?;

    let mut file =
        std::fs::File::open(local).with_context(|| format!("opening {}", local.display()))?;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", local.display()))?;
        if n == 0 {
            break;
        }
        send.send_data(Bytes::from(quish_proto::encode(&ChannelMessage::Data(
            buf[..n].to_vec(),
        ))?))
        .await
        .context("sending upload data")?;
    }
    send.finish().await.context("finishing upload send")?;

    await_status(recv)
        .await?
        .with_context(|| format!("upload of {remote} ended without a status"))
}

/// Create the single remote directory `remote` (mode `& 0o777`); the client
/// creates parents first, so this never needs `mkdir -p`.
async fn mkdir_one(
    send_request: &mut crate::SendRequest,
    target: &crate::Target,
    authorization: &str,
    remote: &str,
    mode: u32,
) -> Result<i32> {
    let (mut send, recv) = crate::open_channel(send_request, target, authorization).await?;
    send.send_data(Bytes::from(quish_proto::encode(&ChannelOpen::MkDir {
        path: remote.to_string(),
        mode,
    })?))
    .await
    .context("sending MkDir open")?;
    send.finish().await.context("finishing mkdir send")?;

    await_status(recv)
        .await?
        .with_context(|| format!("mkdir of {remote} ended without a status"))
}

/// Upload a directory tree: mkdir the remote root, then each subdir top-down,
/// then each regular file (printing its relative path to stderr). The first
/// nonzero status aborts and becomes the returned exit code.
async fn upload_tree(
    send_request: &mut crate::SendRequest,
    target: &crate::Target,
    authorization: &str,
    local_root: &std::path::Path,
    remote_root: &str,
    root_mode: u32,
    walk: &Walk,
) -> Result<i32> {
    let code = mkdir_one(send_request, target, authorization, remote_root, root_mode).await?;
    if code != 0 {
        eprintln!("quish: mkdir of {remote_root} failed (status {code})");
        return Ok(code);
    }
    for d in &walk.dirs {
        let remote = format!("{remote_root}/{}", d.rel);
        eprintln!("{}/", d.rel);
        let code = mkdir_one(send_request, target, authorization, &remote, d.mode).await?;
        if code != 0 {
            eprintln!("quish: mkdir of {remote} failed (status {code})");
            return Ok(code);
        }
    }
    for f in &walk.files {
        let local = local_root.join(&f.rel);
        let remote = format!("{remote_root}/{}", f.rel);
        eprintln!("{}", f.rel);
        let code = upload_one(send_request, target, authorization, &local, &remote).await?;
        if code != 0 {
            eprintln!("quish: upload of {remote} failed (status {code})");
            return Ok(code);
        }
    }
    Ok(0)
}

/// Read frames until the terminal `ExitStatus`; `None` if the stream ends first.
async fn await_status(recv: crate::RecvHalf) -> Result<Option<i32>> {
    let mut reader = crate::ChannelFrameReader::new(recv);
    while let Some(msg) = reader.next().await? {
        if let ChannelMessage::ExitStatus(c) = msg {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_no_user() {
        assert_eq!(
            parse_cp_spec("host:/a").unwrap(),
            CpSpec::Remote {
                user: None,
                host: "host".into(),
                path: "/a".into()
            }
        );
    }

    #[test]
    fn parse_remote_with_user() {
        assert_eq!(
            parse_cp_spec("alice@host:/a").unwrap(),
            CpSpec::Remote {
                user: Some("alice".into()),
                host: "host".into(),
                path: "/a".into()
            }
        );
    }

    #[test]
    fn parse_remote_ipv6() {
        assert_eq!(
            parse_cp_spec("[::1]:/a").unwrap(),
            CpSpec::Remote {
                user: None,
                host: "::1".into(),
                path: "/a".into()
            }
        );
    }

    #[test]
    fn parse_remote_empty_path() {
        assert_eq!(
            parse_cp_spec("host:").unwrap(),
            CpSpec::Remote {
                user: None,
                host: "host".into(),
                path: "".into()
            }
        );
    }

    #[test]
    fn parse_local_slash_before_colon() {
        assert_eq!(
            parse_cp_spec("./x:y").unwrap(),
            CpSpec::Local("./x:y".into())
        );
    }

    #[test]
    fn parse_local_absolute_with_colon() {
        assert_eq!(parse_cp_spec("/a:b").unwrap(), CpSpec::Local("/a:b".into()));
    }

    #[test]
    fn parse_local_plain() {
        assert_eq!(
            parse_cp_spec("plain").unwrap(),
            CpSpec::Local("plain".into())
        );
    }

    #[test]
    fn parse_empty_host_errors() {
        assert!(parse_cp_spec(":/a").is_err());
    }

    #[test]
    fn parse_bracket_without_colon_errors() {
        assert!(parse_cp_spec("[::1]/a").is_err());
    }

    #[test]
    fn resolve_local_into_existing_dir() {
        assert_eq!(
            resolve_local_dst("dir", true, "/x/y.txt").unwrap(),
            std::path::PathBuf::from("dir/y.txt")
        );
    }

    #[test]
    fn resolve_local_trailing_slash_appends_basename() {
        assert_eq!(
            resolve_local_dst("dir/", false, "/x/y.txt").unwrap(),
            std::path::PathBuf::from("dir/y.txt")
        );
    }

    #[test]
    fn resolve_local_plain_file_is_itself() {
        assert_eq!(
            resolve_local_dst("out.txt", false, "/x/y.txt").unwrap(),
            std::path::PathBuf::from("out.txt")
        );
    }

    #[test]
    fn resolve_local_remote_trailing_slash_errors() {
        assert!(resolve_local_dst("dir", true, "/x/").is_err());
    }

    #[test]
    fn resolve_remote_trailing_slash() {
        assert_eq!(resolve_remote_dst("docs/", "f"), "docs/f");
    }

    #[test]
    fn resolve_remote_empty_is_basename() {
        assert_eq!(resolve_remote_dst("", "f"), "f");
    }

    #[test]
    fn resolve_remote_dot() {
        assert_eq!(resolve_remote_dst(".", "f"), "./f");
    }

    #[test]
    fn resolve_remote_exact() {
        assert_eq!(resolve_remote_dst("exact", "f"), "exact");
    }

    /// A `CpArgs` with only the resolution-relevant fields set; src/dst are
    /// unused by `resolve_cp_target` (it takes user/host separately).
    fn cp_args(port: Option<u16>, connect_path: Option<String>) -> CpArgs {
        CpArgs {
            src: "x".into(),
            dst: "y".into(),
            identity: None,
            port,
            connect_path,
        }
    }

    /// A `[hosts.<alias>]` block carrying a custom secret `path`.
    fn block_with_path(host: &str, path: &str) -> crate::config::HostBlock {
        crate::config::HostBlock {
            host: host.into(),
            port: None,
            user: None,
            path: Some(path.into()),
            identity: None,
            local_forward: vec![],
            remote_forward: vec![],
        }
    }

    // The regression: no --connect-path flag → a host block's `path` wins.
    #[test]
    fn cp_uses_block_path_when_flag_absent() {
        let mut cfg = crate::config::ClientConfig::default();
        cfg.hosts
            .insert("box".into(), block_with_path("host.example.com", "/custom"));
        let args = cp_args(None, None);
        let (target, _) = resolve_cp_target(None, "box".into(), &args, &cfg).unwrap();
        assert_eq!(target.host, "host.example.com");
        assert_eq!(target.path, "/custom");
    }

    // An explicit --connect-path still overrides a block's `path`.
    #[test]
    fn cp_flag_beats_block_path() {
        let mut cfg = crate::config::ClientConfig::default();
        cfg.hosts
            .insert("box".into(), block_with_path("host.example.com", "/custom"));
        let args = cp_args(None, Some("/flag".into()));
        let (target, _) = resolve_cp_target(None, "box".into(), &args, &cfg).unwrap();
        assert_eq!(target.path, "/flag");
    }

    // No flag and no block: the built-in default.
    #[test]
    fn cp_defaults_to_quish_path() {
        let cfg = crate::config::ClientConfig::default();
        let args = cp_args(None, None);
        let (target, _) =
            resolve_cp_target(None, "literal.example.com".into(), &args, &cfg).unwrap();
        assert_eq!(target.path, quish_proto::DEFAULT_PATH);
    }
}
