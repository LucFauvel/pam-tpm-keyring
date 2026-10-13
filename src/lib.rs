//! pam_tpm_keyring: fingerprint login that also unlocks the GNOME keyring.
//!
//! A fingerprint login never produces a password, so pam_gnome_keyring has
//! nothing to unlock the login keyring with. After `pam-tpm-keyring setup`, the
//! login keyring's password is a random key instead of the login password.
//! The key is kept twice (see `slot`): sealed to the TPM (PCR 7, the Secure
//! Boot state) for fingerprint logins, and wrapped with the login password for
//! password logins. Either way this module hands the key to pam_gnome_keyring
//! as PAM_AUTHTOK, so the login password itself is never stored.
//!
//! Module arguments (one mode is required in the auth stack):
//! - `fingerprint`: ask for the password. If one was typed, set it as
//!   PAM_AUTHTOK and return PAM_IGNORE so the password modules that follow
//!   check it. If it was empty, verify a fingerprint through fprintd instead:
//!   on a match, set the keyring key as PAM_AUTHTOK and return PAM_SUCCESS.
//!   Otherwise return PAM_AUTH_ERR. Pressing any key or mouse button cancels
//!   the scan. The key is unsealed before scanning; if that fails (PCR 7
//!   changed), no scan is started and the greeter is told to ask for the
//!   password instead, whose login reseals the key.
//! - `seal`: password path, after pam_unix accepted PAM_AUTHTOK. Open the slot
//!   with it, reseal the key to the TPM if needed (only while Secure Boot is
//!   enforced), and replace PAM_AUTHTOK with the key. If the slot doesn't open
//!   (the password was changed without this module), take the key from the TPM
//!   and rewrap it with the new password.
//! - `unseal`: for stacks that use pam_fprintd. Set the keyring key as
//!   PAM_AUTHTOK.
//! - `allow-locked`: in `fingerprint` mode, scan anyway when unsealing fails.
//!   The login then works but the keyring stays locked.
//! - `max-tries=N`: non-matching scans allowed in `fingerprint` mode (default 3).
//! - `debug`: log every step, not just failures.
//!
//! In the password stack (no mode), a password change rewraps the key with
//! the new password.
//!
//! `seal` and `unseal` always return PAM_IGNORE: they never authenticate
//! anyone, so even a `sufficient` control can't turn them into a bypass. Only
//! a fingerprint match in `fingerprint` mode returns PAM_SUCCESS. Failing to
//! unlock the keyring never blocks a login: the keyring just stays locked.
//! Users who haven't run setup get plain fingerprint login.

pub mod account;
pub mod control;
mod fingerprint;
mod input;
pub mod slot;
pub mod state;
pub mod tpm;

use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use fingerprint::Outcome;
use slot::OpenError;
use tpm::Secret;

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_IGNORE: c_int = 25;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const PAM_UPDATE_AUTHTOK: c_int = 0x2000;

const LOG_ERR: c_int = 3;
const LOG_INFO: c_int = 6;

const DEFAULT_MAX_TRIES: u32 = 3;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_prompt(pamh: *mut PamHandle, style: c_int, response: *mut *mut c_char, fmt: *const c_char, ...) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
    fn free(ptr: *mut c_void);
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Fingerprint,
    Seal,
    Unseal,
}

struct Args {
    mode: Option<Mode>,
    allow_locked: bool,
    max_tries: u32,
    debug: bool,
}

struct Pam {
    handle: *mut PamHandle,
    debug: bool,
}

/// Turns `msg` into a C string, replacing any NUL bytes.
fn c_string(msg: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = msg.bytes().map(|b| if b == 0 { b'?' } else { b }).collect();
    buf.push(0);
    buf
}

impl Pam {
    fn log(&self, priority: c_int, msg: &str) {
        let buf = c_string(msg);
        unsafe { pam_syslog(self.handle, priority, c"%s".as_ptr(), buf.as_ptr() as *const c_char) };
    }

    fn debug(&self, msg: &str) {
        if self.debug {
            self.log(LOG_INFO, msg);
        }
    }

    /// Shows a status message to the user.
    fn info(&self, msg: &str) {
        let buf = c_string(msg);
        unsafe {
            pam_prompt(
                self.handle,
                PAM_TEXT_INFO,
                std::ptr::null_mut(),
                c"%s".as_ptr(),
                buf.as_ptr() as *const c_char,
            )
        };
    }

    fn prompt_password(&self) -> Result<Secret, String> {
        let mut resp: *mut c_char = std::ptr::null_mut();
        let ret = unsafe {
            pam_prompt(self.handle, PAM_PROMPT_ECHO_OFF, &mut resp, c"%s".as_ptr(), c"Password: ".as_ptr())
        };
        if ret != PAM_SUCCESS {
            return Err(format!("password prompt failed ({ret})"));
        }
        if resp.is_null() {
            return Ok(Secret::with_capacity(0));
        }
        let (secret, len) = {
            let bytes = unsafe { CStr::from_ptr(resp) }.to_bytes();
            (Secret::from_bytes(bytes), bytes.len())
        };
        // `bytes` is gone before the buffer is written through `resp`.
        unsafe {
            std::ptr::write_bytes(resp, 0, len);
            free(resp as *mut c_void);
        }
        Ok(secret)
    }

    fn user(&self) -> Result<String, String> {
        let mut user: *const c_char = std::ptr::null();
        let ret = unsafe { pam_get_user(self.handle, &mut user, std::ptr::null()) };
        if ret != PAM_SUCCESS || user.is_null() {
            return Err(format!("pam_get_user failed ({ret})"));
        }
        let user = unsafe { CStr::from_ptr(user) };
        user.to_str()
            .map(str::to_owned)
            .map_err(|_| "user name is not valid UTF-8".into())
    }

    /// PAM_AUTHTOK or PAM_OLDAUTHTOK, if set and not empty.
    fn token(&self, item_type: c_int) -> Option<Secret> {
        let mut item: *const c_void = std::ptr::null();
        let ret = unsafe { pam_get_item(self.handle, item_type, &mut item) };
        if ret != PAM_SUCCESS || item.is_null() {
            return None;
        }
        let bytes = unsafe { CStr::from_ptr(item as *const c_char) }.to_bytes();
        Some(Secret::from_bytes(bytes)).filter(|s| !s.0.is_empty())
    }

    fn set_authtok(&self, secret: &Secret) -> Result<(), String> {
        if secret.0.contains(&0) {
            return Err("password contains a NUL byte".into());
        }
        let mut buf = Secret::with_capacity(secret.0.len() + 1);
        buf.0.extend_from_slice(&secret.0);
        buf.0.push(0);
        // PAM copies the string, so `buf` can be wiped afterwards.
        let ret = unsafe { pam_set_item(self.handle, PAM_AUTHTOK, buf.0.as_ptr() as *const c_void) };
        if ret != PAM_SUCCESS {
            return Err(format!("pam_set_item(PAM_AUTHTOK) failed ({ret})"));
        }
        Ok(())
    }

    /// Sets the TPM-sealed keyring key as PAM_AUTHTOK. Failure only means the
    /// keyring stays locked, so it is logged, not returned.
    fn unseal_into_authtok(&self, user: &str) {
        match tpm::unseal(user).and_then(|key| self.set_authtok(&key)) {
            Ok(()) => self.debug(&format!("unsealed the keyring key for {user}")),
            Err(e) => self.log(LOG_ERR, &format!("keyring stays locked: {e}")),
        }
    }
}

fn fingerprint(pam: &Pam, user: &str, args: &Args) -> Result<c_int, String> {
    let typed = pam.prompt_password()?;
    if !typed.0.is_empty() {
        pam.set_authtok(&typed)?;
        pam.debug("password typed, leaving it to the password modules");
        return Ok(PAM_IGNORE);
    }

    // Unseal first, so a keyring that can't be unlocked is reported before the
    // user touches the sensor, not after.
    let key = if !slot::exists(user) {
        pam.log(LOG_INFO, &format!("keyring unlock isn't set up for {user} (pam-tpm-keyring setup)"));
        None
    } else {
        match tpm::unseal(user) {
            Ok(key) => Some(key),
            Err(e) if args.allow_locked => {
                pam.log(LOG_ERR, &format!("keyring will stay locked: {e}"));
                None
            }
            Err(e) => {
                pam.log(LOG_ERR, &format!("cannot unseal the keyring key, asking for the password: {e}"));
                pam.info(fingerprint::MSG_NEEDS_PASSWORD);
                return Ok(PAM_AUTH_ERR);
            }
        }
    };


    let outcome = fingerprint::verify(user, args.max_tries, &|msg| pam.info(msg), &|e| pam.log(LOG_ERR, e));
    match outcome {
        Outcome::Match => {
            pam.debug(&format!("fingerprint matched for {user}"));
            if let Some(key) = key {
                match pam.set_authtok(&key) {
                    Ok(()) => pam.debug(&format!("unlocking the keyring with the unsealed key for {user}")),
                    Err(e) => pam.log(LOG_ERR, &format!("keyring stays locked: {e}")),
                }
            }
            Ok(PAM_SUCCESS)
        }
        Outcome::Cancelled => {
            pam.debug("fingerprint scan cancelled by input");
            pam.info(fingerprint::MSG_CANCELLED);
            Ok(PAM_AUTH_ERR)
        }
        Outcome::Failed(msg) => {
            pam.debug(&format!("fingerprint failed: {msg}"));
            pam.info(msg);
            Ok(PAM_AUTH_ERR)
        }
    }
}

fn seal(pam: &Pam, user: &str) -> Result<c_int, String> {
    let Some(password) = pam.token(PAM_AUTHTOK) else {
        pam.debug("no password");
        return Ok(PAM_IGNORE);
    };
    let key = match slot::open(user, &password) {
        Ok(key) => key,
        Err(OpenError::Missing) => {
            pam.debug(&format!("keyring unlock isn't set up for {user}"));
            return Ok(PAM_IGNORE);
        }
        Err(e) => {
            // The password was changed without this module (or the slot is
            // damaged); the TPM still has the key. Rewrapping replaces the
            // slot, so don't take the stack's word that the password is right.
            if !account::check_password(user, &password)? {
                return Err(format!("{}, and it isn't the login password: not rewrapping", e.describe()));
            }
            let key = tpm::unseal(user).map_err(|t| {
                format!("keyring stays locked: {}, and the TPM copy can't be unsealed ({t})", e.describe())
            })?;
            match slot::store(user, &password, &key) {
                Ok(()) => pam.log(LOG_INFO, &format!("rewrapped the keyring key for {user} with the current password")),
                Err(e) => pam.log(LOG_ERR, &format!("cannot rewrap the keyring key: {e}")),
            }
            key
        }
    };

    if !tpm::secure_boot_enforced() {
        pam.debug("Secure Boot is not enforced, not sealing");
    } else {
        match tpm::unseal(user) {
            Ok(stored) if stored.0 == key.0 => pam.debug(&format!("sealed key for {user} is current")),
            _ => match tpm::seal(user, &key) {
                Ok(()) => pam.log(LOG_INFO, &format!("sealed the keyring key for {user} to the TPM")),
                Err(e) => pam.log(LOG_ERR, &format!("cannot seal the keyring key: {e}")),
            },
        }
    }

    pam.set_authtok(&key)?;
    pam.debug("unlocking the keyring with the key from the password slot");
    Ok(PAM_IGNORE)
}

/// Password stack: follow a password change by rewrapping the keyring key
/// with the new password.
fn change_password(pam: &Pam, user: &str) -> Result<c_int, String> {
    if !slot::exists(user) {
        return Ok(PAM_IGNORE);
    }
    let Some(new) = pam.token(PAM_AUTHTOK) else {
        pam.debug("no new password");
        return Ok(PAM_IGNORE);
    };
    // Only follow a change that actually happened.
    if !account::check_password(user, &new)? {
        pam.log(LOG_ERR, "the password wasn't changed, keeping the password slot");
        return Ok(PAM_IGNORE);
    }
    // Root changing someone else's password doesn't know the old one.
    let key = match pam.token(PAM_OLDAUTHTOK).map(|old| slot::open(user, &old)) {
        Some(Ok(key)) => key,
        _ => tpm::unseal(user).map_err(|e| {
            format!("cannot rewrap the keyring key, it is still wrapped with the old password: the TPM copy can't be unsealed ({e})")
        })?,
    };
    slot::store(user, &new, &key)?;
    pam.log(LOG_INFO, &format!("rewrapped the keyring key for {user} with the new password"));
    Ok(PAM_IGNORE)
}

fn authenticate(pam: &Pam, args: &Args) -> Result<c_int, String> {
    let Some(mode) = args.mode else {
        return Err("missing mode argument (fingerprint, seal or unseal)".into());
    };
    let user = pam.user()?;
    if !tpm::valid_user(&user) {
        return Err(format!("refusing unusual user name {user:?}"));
    }
    match mode {
        Mode::Fingerprint => fingerprint(pam, &user, args),
        Mode::Seal => seal(pam, &user),
        Mode::Unseal => {
            pam.unseal_into_authtok(&user);
            Ok(PAM_IGNORE)
        }
    }
}

fn parse_args(argc: c_int, argv: *const *const c_char) -> Result<Args, String> {
    let mut args = Args { mode: None, allow_locked: false, max_tries: DEFAULT_MAX_TRIES, debug: false };
    for i in 0..argc.max(0) as usize {
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) };
        let arg = arg.to_str().map_err(|_| "argument is not valid UTF-8".to_string())?;
        match arg {
            "fingerprint" => args.mode = Some(Mode::Fingerprint),
            "seal" => args.mode = Some(Mode::Seal),
            "unseal" => args.mode = Some(Mode::Unseal),
            "allow-locked" => args.allow_locked = true,
            "debug" => args.debug = true,
            _ => match arg.strip_prefix("max-tries=").map(str::parse) {
                Some(Ok(n)) if n > 0 => args.max_tries = n,
                _ => return Err(format!("bad argument {arg:?}")),
            },
        }
    }
    Ok(args)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let args = match parse_args(argc, argv) {
            Ok(args) => args,
            Err(e) => {
                Pam { handle: pamh, debug: true }.log(LOG_ERR, &e);
                return PAM_IGNORE;
            }
        };
        let pam = Pam { handle: pamh, debug: args.debug };
        authenticate(&pam, &args).unwrap_or_else(|e| {
            pam.log(LOG_ERR, &e);
            PAM_IGNORE
        })
    }));
    result.unwrap_or(PAM_IGNORE)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Called twice: a preliminary check, then the update.
    if flags & PAM_UPDATE_AUTHTOK == 0 {
        return PAM_IGNORE;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let args = match parse_args(argc, argv) {
            Ok(args) => args,
            Err(e) => {
                Pam { handle: pamh, debug: true }.log(LOG_ERR, &e);
                return PAM_IGNORE;
            }
        };
        let pam = Pam { handle: pamh, debug: args.debug };
        let result = pam.user().and_then(|user| {
            if !tpm::valid_user(&user) {
                return Err(format!("refusing unusual user name {user:?}"));
            }
            change_password(&pam, &user)
        });
        result.unwrap_or_else(|e| {
            pam.log(LOG_ERR, &e);
            PAM_IGNORE
        })
    }));
    result.unwrap_or(PAM_IGNORE)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
