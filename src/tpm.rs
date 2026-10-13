//! TPM-sealed copies of the keyring key, stored by systemd-creds.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{Ordering, compiler_fence};

use crate::state::{self, Pending};

const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const MAX_SECRET_LEN: usize = 4096;
const ECHILD: i32 = 10;

/// A password buffer that is wiped when dropped.
pub struct Secret(pub Vec<u8>);

impl Secret {
    pub fn with_capacity(cap: usize) -> Self {
        Secret(Vec::with_capacity(cap))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut secret = Secret::with_capacity(bytes.len());
        secret.0.extend_from_slice(bytes);
        secret
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Wipe the whole allocation, not just the initialized part.
        let ptr = self.0.as_mut_ptr();
        for i in 0..self.0.capacity() {
            unsafe { ptr.add(i).write_volatile(0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// The user name ends up in a file path and a credential name, so only allow
/// what useradd allows by default.
pub fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && !user.starts_with(['-', '.'])
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn cred_file(user: &str) -> String {
    format!("{user}.cred")
}

fn cred_path(user: &str) -> PathBuf {
    state::path(&cred_file(user))
}

fn cred_name(user: &str) -> String {
    // The name is authenticated by systemd-creds, so one user's blob can't be
    // swapped in for another's.
    format!("pam-tpm-keyring-{user}")
}

fn efi_var_byte(name: &str) -> Option<u8> {
    // efivarfs files start with a 4-byte attribute field.
    let data = fs::read(format!("/sys/firmware/efi/efivars/{name}-{EFI_GLOBAL_GUID}")).ok()?;
    data.get(4).copied()
}

pub fn secure_boot_enforced() -> bool {
    efi_var_byte("SecureBoot") == Some(1) && efi_var_byte("SetupMode") == Some(0)
}

/// Runs systemd-creds, feeding it `input` and returning its stdout.
fn systemd_creds(args: &[&str], input: Option<&Secret>) -> Result<Secret, String> {
    let mut child = Command::new(SYSTEMD_CREDS)
        .args(args)
        .env_clear()
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {SYSTEMD_CREDS}: {e}"))?;

    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin
            .write_all(&input.0)
            .map_err(|e| format!("cannot write to systemd-creds: {e}"))?;
    }

    let mut out = Secret::with_capacity(MAX_SECRET_LEN);
    let mut stdout = child.stdout.take().expect("stdout is piped");
    (&mut stdout)
        .take(MAX_SECRET_LEN as u64)
        .read_to_end(&mut out.0)
        .map_err(|e| format!("cannot read from systemd-creds: {e}"))?;
    let mut err = String::new();
    let _ = child.stderr.take().expect("stderr is piped").read_to_string(&mut err);
    if out.0.len() >= MAX_SECRET_LEN {
        let _ = child.kill();
        let _ = child.wait();
        return Err("systemd-creds output is too long".into());
    }

    match child.wait() {
        Ok(status) if status.success() => Ok(out),
        Ok(status) => Err(format!("systemd-creds {} failed ({status}): {}", args[0], err.trim())),
        // The PAM application may reap children itself (SIGCHLD handler). The
        // exit status is lost then; decide from the output instead.
        Err(e) if e.raw_os_error() == Some(ECHILD) && err.is_empty() => Ok(out),
        Err(e) => Err(format!("cannot wait for systemd-creds: {e}")),
    }
}

fn decrypt(path: &Path, name: &str) -> Result<Secret, String> {
    let path = path.to_str().expect("path is ASCII");
    let secret = systemd_creds(&["decrypt", &format!("--name={name}"), path, "-"], None)?;
    if secret.0.is_empty() {
        return Err("sealed key is empty".into());
    }
    Ok(secret)
}

pub fn unseal(user: &str) -> Result<Secret, String> {
    let path = cred_path(user);
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    state::check_dir()?;
    decrypt(&path, &cred_name(user))
}

/// Seals `secret` for `user`, without replacing the stored copy until the
/// result is committed.
pub fn seal_pending(user: &str, secret: &Secret) -> Result<Pending, String> {
    let pending = Pending::new(&cred_file(user))?;
    let tmp = pending.tmp_path();
    let name = cred_name(user);
    systemd_creds(
        &[
            "encrypt",
            "--with-key=tpm2",
            "--tpm2-pcrs=7",
            &format!("--name={name}"),
            "-",
            tmp.to_str().expect("path is ASCII"),
        ],
        Some(secret),
    )?;

    // Only accept a sealed copy that is known to decrypt to the right secret
    // (the exit status of systemd-creds may have been lost).
    match decrypt(tmp, &name) {
        Ok(check) if check.0 == secret.0 => {}
        Ok(_) => return Err("new sealed copy doesn't match, keeping the old one".into()),
        Err(e) => return Err(format!("new sealed copy doesn't decrypt ({e}), keeping the old one")),
    }
    fs::set_permissions(tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot chmod {}: {e}", tmp.display()))?;
    Ok(pending)
}

pub fn seal(user: &str, secret: &Secret) -> Result<(), String> {
    seal_pending(user, secret)?.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_names() {
        assert!(valid_user("alice"));
        assert!(valid_user("first.last_2-x"));
        assert!(!valid_user(""));
        assert!(!valid_user("../root"));
        assert!(!valid_user("a/b"));
        assert!(!valid_user(".hidden"));
        assert!(!valid_user("-rf"));
        assert!(!valid_user("name with space"));
        assert!(!valid_user(&"a".repeat(33)));
    }

    #[test]
    fn paths() {
        assert_eq!(cred_path("alice"), Path::new("/var/lib/pam-tpm-keyring/alice.cred"));
        assert_eq!(cred_name("alice"), "pam-tpm-keyring-alice");
    }
}
