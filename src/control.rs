//! gnome-keyring-daemon's control socket, the one pam_gnome_keyring uses to
//! unlock the login keyring and change its password.
//!
//! Protocol (gkr-pam-client.c): one credentials byte, then
//! `[u32 length][u32 op]([u32 len][bytes])*`, all big-endian, where length
//! counts itself and the op. The reply is `[u32 8][u32 result]`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::account::Ids;
use crate::tpm::Secret;

const OP_UNLOCK: u32 = 1;
const OP_CHANGE: u32 = 2;
const RESULT_OK: u32 = 0;
const RESULT_DENIED: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(30);

/// Connects to `ids`'s keyring daemon. The daemon only talks to its own user,
/// so this switches the effective uid for the connect. Must be called as root
/// from a single-threaded process.
///
/// The user controls the socket's directory, so the connect must not be able
/// to reach anything the user couldn't: root's supplementary groups are
/// dropped for it too.
fn connect(ids: &Ids) -> Result<UnixStream, String> {
    let path = format!("/run/user/{}/keyring/control", ids.uid);
    let mut groups = vec![0 as libc::gid_t; 256];
    let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if n < 0 {
        return Err(format!("getgroups failed: {}", std::io::Error::last_os_error()));
    }
    groups.truncate(n as usize);

    let restore = || unsafe {
        if libc::seteuid(0) != 0 || libc::setegid(0) != 0 || libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            // Carrying on as the user would be wrong either way.
            std::process::abort();
        }
    };
    unsafe {
        if libc::setgroups(1, &ids.gid) != 0 || libc::setegid(ids.gid) != 0 || libc::seteuid(ids.uid) != 0 {
            let err = std::io::Error::last_os_error();
            restore();
            return Err(format!("cannot switch to uid {}: {err}", ids.uid));
        }
    }
    let stream = UnixStream::connect(&path);
    restore();
    stream.map_err(|e| format!("cannot connect to {path} (is the user logged in?): {e}"))
}

/// Unlocks the login keyring with `password`.
pub fn unlock(ids: &Ids, password: &Secret) -> Result<(), String> {
    request(connect(ids)?, OP_UNLOCK, &[password])
}

/// Changes the login keyring's password from `old` to `new`.
pub fn change_password(ids: &Ids, old: &Secret, new: &Secret) -> Result<(), String> {
    request(connect(ids)?, OP_CHANGE, &[old, new])
}

fn request(mut stream: UnixStream, op: u32, args: &[&Secret]) -> Result<(), String> {
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

    let len = 8 + args.iter().map(|arg| 4 + arg.0.len()).sum::<usize>();
    let mut packet = Secret::with_capacity(1 + len);
    packet.0.push(0); // credentials byte
    packet.0.extend_from_slice(&(len as u32).to_be_bytes());
    packet.0.extend_from_slice(&op.to_be_bytes());
    for arg in args {
        packet.0.extend_from_slice(&(arg.0.len() as u32).to_be_bytes());
        packet.0.extend_from_slice(&arg.0);
    }
    stream.write_all(&packet.0).map_err(|e| format!("cannot talk to the keyring daemon: {e}"))?;

    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).map_err(|e| format!("no reply from the keyring daemon: {e}"))?;
    let result = u32::from_be_bytes(reply[4..].try_into().expect("4 bytes"));
    match result {
        RESULT_OK => Ok(()),
        RESULT_DENIED => Err("the keyring daemon refused: wrong keyring password".into()),
        other => Err(format!("the keyring daemon failed (result {other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against a throwaway daemon: GKR_CONTROL=<dir>/control, whose login
    /// keyring opens with "pw1". Leaves it opening with "pw2".
    #[test]
    #[ignore]
    fn live_change() {
        let path = std::env::var("GKR_CONTROL").expect("GKR_CONTROL");
        let connect = || UnixStream::connect(&path).unwrap();
        let (pw1, pw2) = (Secret::from_bytes(b"pw1"), Secret::from_bytes(b"pw2"));
        let nope = Secret::from_bytes(b"nope");
        assert!(request(connect(), OP_CHANGE, &[&nope, &pw2]).unwrap_err().contains("wrong"));
        request(connect(), OP_CHANGE, &[&pw1, &pw2]).unwrap();
        assert!(request(connect(), OP_CHANGE, &[&pw1, &pw2]).is_err());
        request(connect(), OP_UNLOCK, &[&pw2]).unwrap();
    }
}
