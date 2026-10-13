//! The user's account: password check and uid lookup.

use std::ffi::CString;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::tpm::Secret;

const UNIX_CHKPWD: &str = "/usr/bin/unix_chkpwd";

/// Whether `password` is `user`'s current login password, asked of pam_unix's
/// helper so the answer comes from the same place as a real login's.
pub fn check_password(user: &str, password: &Secret) -> Result<bool, String> {
    let mut child = Command::new(UNIX_CHKPWD)
        .args([user, "nullok"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run {UNIX_CHKPWD}: {e}"))?;
    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        // The helper reads a NUL-terminated password.
        let mut buf = Secret::with_capacity(password.0.len() + 1);
        buf.0.extend_from_slice(&password.0);
        buf.0.push(0);
        stdin.write_all(&buf.0).map_err(|e| format!("cannot write to {UNIX_CHKPWD}: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("cannot wait for {UNIX_CHKPWD}: {e}"))?;
    Ok(status.success())
}

pub struct Ids {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

pub fn lookup(user: &str) -> Result<Ids, String> {
    let name = CString::new(user).map_err(|_| "bad user name".to_string())?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let ret = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if ret != 0 || result.is_null() {
        return Err(format!("no such user {user:?}"));
    }
    Ok(Ids { uid: pwd.pw_uid, gid: pwd.pw_gid })
}
