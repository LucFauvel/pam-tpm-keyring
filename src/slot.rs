//! The keyring key, wrapped with the login password.
//!
//! The login keyring's password is a random key, not the login password. The
//! TPM holds one copy of it (for fingerprint logins); this file holds another,
//! encrypted with a key derived from the login password (for password logins,
//! and for when the TPM copy can't be unsealed). Like a LUKS key slot.
//!
//! File layout: header | ChaCha20-Poly1305 ciphertext of the key | tag, where
//! header = "PTK1" | Argon2id m_cost, t_cost, p_cost (u32 LE) | salt | nonce.
//! The header and the user name are authenticated as associated data.

use std::fs;
use std::io::ErrorKind;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::state::{self, Pending};
use crate::tpm::Secret;

const MAGIC: &[u8; 4] = b"PTK1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 12 + SALT_LEN + NONCE_LEN;
const KEY_LEN: usize = 32;
const MAX_FILE_LEN: usize = 4096;

// Argon2id with 64 MiB, 3 passes: RFC 9106's second recommended setting.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
/// Refuse files asking for more than this, so a bad file can't exhaust memory
/// or hang the login.
const MAX_M_COST: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

pub enum OpenError {
    Missing,
    WrongPassword,
    Bad(String),
}

impl OpenError {
    pub fn describe(&self) -> String {
        match self {
            OpenError::Missing => "no password slot".into(),
            OpenError::WrongPassword => "the password doesn't open the slot".into(),
            OpenError::Bad(e) => e.clone(),
        }
    }
}

fn file(user: &str) -> String {
    format!("{user}.slot")
}

pub fn exists(user: &str) -> bool {
    state::path(&file(user)).exists()
}

/// Fills `buf` from the kernel's random number generator.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("getrandom failed: {err}"));
        }
        filled += n as usize;
    }
    Ok(())
}

/// A new random keyring key, as 64 hex digits (it is used as a password).
pub fn new_key() -> Result<Secret, String> {
    let mut raw = Secret(vec![0; KEY_LEN]);
    random_bytes(&mut raw.0)?;
    let mut key = Secret::with_capacity(KEY_LEN * 2);
    for b in &raw.0 {
        key.0.push(b"0123456789abcdef"[(b >> 4) as usize]);
        key.0.push(b"0123456789abcdef"[(b & 15) as usize]);
    }
    Ok(key)
}

fn derive(password: &Secret, m: u32, t: u32, p: u32, salt: &[u8]) -> Result<Secret, String> {
    let params = Params::new(m, t, p, Some(KEY_LEN)).map_err(|e| format!("bad Argon2 parameters: {e}"))?;
    let mut out = Secret(vec![0; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&password.0, salt, &mut out.0)
        .map_err(|e| format!("Argon2 failed: {e}"))?;
    Ok(out)
}

fn aad(header: &[u8], user: &str) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(user.as_bytes());
    aad
}

fn wrap(user: &str, password: &Secret, key: &Secret) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut salt)?;
    random_bytes(&mut nonce)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    for v in [M_COST, T_COST, P_COST] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let kek = derive(password, M_COST, T_COST, P_COST, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&kek.0).expect("key is 32 bytes");
    let nonce = Nonce::try_from(&nonce[..]).expect("nonce is 12 bytes");
    let sealed = cipher
        .encrypt(&nonce, Payload { msg: &key.0, aad: &aad(&header, user) })
        .map_err(|_| "encryption failed".to_string())?;

    header.extend_from_slice(&sealed);
    Ok(header)
}

fn unwrap(user: &str, password: &Secret, data: &[u8]) -> Result<Secret, OpenError> {
    let bad = |e: &str| OpenError::Bad(format!("{}: {e}", state::path(&file(user)).display()));
    if data.len() <= HEADER_LEN || !data.starts_with(MAGIC) {
        return Err(bad("not a password slot"));
    }
    let (header, sealed) = data.split_at(HEADER_LEN);
    let u32_at = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().expect("4 bytes"));
    let (m, t, p) = (u32_at(4), u32_at(8), u32_at(12));
    if m > MAX_M_COST || t > MAX_T_COST || p > MAX_P_COST {
        return Err(bad("Argon2 cost too high"));
    }
    let salt = &header[16..16 + SALT_LEN];
    let nonce = Nonce::try_from(&header[16 + SALT_LEN..]).expect("nonce is 12 bytes");

    let kek = derive(password, m, t, p, salt).map_err(|e| bad(&e))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&kek.0).expect("key is 32 bytes");
    // A wrong password and a tampered file look the same to the AEAD.
    let key = cipher
        .decrypt(&nonce, Payload { msg: sealed, aad: &aad(header, user) })
        .map_err(|_| OpenError::WrongPassword)?;
    Ok(Secret(key))
}

/// The keyring key, if `password` opens `user`'s slot.
pub fn open(user: &str, password: &Secret) -> Result<Secret, OpenError> {
    state::check_dir().map_err(OpenError::Bad)?;
    let data = match fs::read(state::path(&file(user))) {
        Ok(data) if data.len() <= MAX_FILE_LEN => data,
        Ok(_) => return Err(OpenError::Bad("password slot is too large".into())),
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(OpenError::Missing),
        Err(e) => return Err(OpenError::Bad(format!("cannot read the password slot: {e}"))),
    };
    unwrap(user, password, &data)
}

/// Wraps `key` with `password`, without replacing the stored slot until the
/// result is committed.
pub fn write_pending(user: &str, password: &Secret, key: &Secret) -> Result<Pending, String> {
    let data = wrap(user, password, key)?;
    // Never store a slot that doesn't open.
    match unwrap(user, password, &data) {
        Ok(check) if check.0 == key.0 => {}
        _ => return Err("new password slot doesn't open, keeping the old one".into()),
    }
    Pending::write(&file(user), &data)
}

pub fn store(user: &str, password: &Secret, key: &Secret) -> Result<(), String> {
    write_pending(user, password, key)?.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let password = Secret::from_bytes(b"correct horse");
        let key = new_key().unwrap();
        assert_eq!(key.0.len(), 64);
        assert!(key.0.iter().all(u8::is_ascii_hexdigit));

        let data = wrap("alice", &password, &key).unwrap();
        assert_eq!(unwrap("alice", &password, &data).ok().unwrap().0, key.0);
        assert!(matches!(unwrap("alice", &Secret::from_bytes(b"wrong"), &data), Err(OpenError::WrongPassword)));
        // Bound to the user name.
        assert!(matches!(unwrap("bob", &password, &data), Err(OpenError::WrongPassword)));
        // The header is authenticated.
        let mut tampered = data.clone();
        tampered[8] ^= 1;
        assert!(unwrap("alice", &password, &tampered).is_err());
    }
}
