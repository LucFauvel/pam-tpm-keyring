//! Commands, run as root while USER is logged in (they talk to USER's keyring
//! daemon):
//! - `setup [USER]`: switch USER's login keyring from the login password to a
//!   random key, kept sealed to the TPM and wrapped with the login password.
//!   Running it again generates a new key.
//! - `unlock [USER]`: unlock USER's login keyring with the key, after asking
//!   for the login password. For sessions not started through SDDM: the
//!   keyring's own prompt would want the key, which nobody knows.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::process::ExitCode;

use pam_tpm_keyring::slot::{self, OpenError};
use pam_tpm_keyring::tpm::{self, Secret};
use pam_tpm_keyring::account::{self, Ids};
use pam_tpm_keyring::control;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["setup"] => setup(None),
        ["setup", user] => setup(Some(user)),
        ["unlock"] => unlock(None),
        ["unlock", user] => unlock(Some(user)),
        _ => {
            eprintln!("usage: pam-tpm-keyring setup|unlock [USER]");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pam-tpm-keyring: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Reads a line from the terminal without echoing it.
fn prompt(msg: &str) -> Result<Secret, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("cannot open the terminal: {e}"))?;
    let fd = tty.as_raw_fd();
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err("cannot read the terminal settings".into());
    }
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL;

    (&tty).write_all(msg.as_bytes()).map_err(|e| e.to_string())?;
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) };
    let mut line = Secret::with_capacity(1024);
    let read = BufReader::with_capacity(1024, &tty).read_until(b'\n', &mut line.0);
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };
    read.map_err(|e| format!("cannot read the password: {e}"))?;
    if line.0.last() == Some(&b'\n') {
        line.0.pop();
    }
    // PAM passwords are C strings; one with a NUL in it could never log in.
    if line.0.contains(&0) {
        return Err("the password contains a NUL byte".into());
    }
    Ok(line)
}

/// The user to act on (default: whoever ran sudo), and their login password.
fn user_and_password(user: Option<&str>) -> Result<(String, Ids, Secret), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("run it as root, with sudo".into());
    }
    let user = match user {
        Some(user) => user.to_owned(),
        None => std::env::var("SUDO_USER").map_err(|_| "which user? Pass it as an argument")?,
    };
    if !tpm::valid_user(&user) {
        return Err(format!("refusing unusual user name {user:?}"));
    }
    let ids = account::lookup(&user)?;
    let password = prompt(&format!("Login password for {user}: "))?;
    if !account::check_password(&user, &password)? {
        return Err("wrong password".into());
    }
    Ok((user, ids, password))
}

fn unlock(user: Option<&str>) -> Result<(), String> {
    let (user, ids, password) = user_and_password(user)?;
    let key = match slot::open(&user, &password) {
        Ok(key) => key,
        Err(e) => tpm::unseal(&user).map_err(|t| format!("{}, and the TPM copy can't be unsealed ({t})", e.describe()))?,
    };
    control::unlock(&ids, &key)?;
    println!("Unlocked {user}'s login keyring.");
    Ok(())
}

fn setup(user: Option<&str>) -> Result<(), String> {
    if !tpm::secure_boot_enforced() {
        return Err("Secure Boot isn't enforced, so the key can't be sealed to the TPM".into());
    }
    let (user, ids, password) = user_and_password(user)?;

    // What the login keyring opens with right now.
    let current = match slot::open(&user, &password) {
        Ok(key) => key,
        Err(OpenError::Missing) => Secret::from_bytes(&password.0),
        Err(_) => match tpm::unseal(&user) {
            Ok(key) => key,
            Err(_) => {
                eprintln!("The password slot doesn't open with this password, and the TPM copy can't be unsealed.");
                let old = prompt("Previous login password: ")?;
                slot::open(&user, &old).map_err(|e| e.describe())?
            }
        },
    };

    let key = slot::new_key()?;
    let slot = slot::write_pending(&user, &password, &key)?;
    let cred = tpm::seal_pending(&user, &key)?;
    control::change_password(&ids, &current, &key)?;

    // The keyring now only opens with `key`. A stale TPM copy heals at the next
    // password login, but losing the slot would lose the key.
    if let Err(e) = slot.commit() {
        eprintln!("The login keyring's password is now: {}", String::from_utf8_lossy(&key.0));
        eprintln!("Keep it somewhere safe and run setup again.");
        return Err(e);
    }
    if let Err(e) = cred.commit() {
        eprintln!("pam-tpm-keyring: {e} (the next password login reseals it)");
    }
    println!("Done: {user}'s login keyring now opens with a random key, sealed to the TPM and wrapped with the login password.");
    Ok(())
}
