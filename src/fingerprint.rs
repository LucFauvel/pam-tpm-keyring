//! Fingerprint verification through fprintd's D-Bus API.
//!
//! This replaces pam_fprintd in the stack so the scan can be abandoned when
//! the user presses a key or clicks (see `input`): SDDM's greeter has no way
//! to cancel a login that is in progress.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dbus::Message;
use dbus::blocking::{Connection, Proxy};
use dbus::message::MatchRule;

use crate::input::InputWatch;

const FPRINT: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER: &str = "net.reactivated.Fprint.Manager";
const DEVICE: &str = "net.reactivated.Fprint.Device";
const ERR_NO_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";
const ERR_IN_USE: &str = "net.reactivated.Fprint.Error.AlreadyInUse";
const ERR_NO_DEVICE: &str = "net.reactivated.Fprint.Error.NoSuchDevice";

/// Opening the device (Claim) can take a few seconds with some drivers.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to keep retrying while a previous login still holds the device.
const CLAIM_RETRY: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
/// Give up on a scan nobody touches, so a stuck fprintd can't hang the login.
/// Reported as a cancellation, so the greeter just starts a new scan.
const SCAN_TIMEOUT: Duration = Duration::from_secs(300);

// Status messages sent to the greeter. The SDDM theme matches on these
// exact strings, so change both together.
pub const MSG_STARTING: &str = "Starting fingerprint reader...";
pub const MSG_READY: &str = "Touch the fingerprint sensor";
pub const MSG_RESCAN: &str = "Try again";
pub const MSG_NO_MATCH: &str = "Not recognized, try again";
pub const MSG_FAILED: &str = "Fingerprint not recognized";
pub const MSG_CANCELLED: &str = "Fingerprint cancelled";
pub const MSG_NO_PRINTS: &str = "No fingerprints enrolled";
pub const MSG_UNAVAILABLE: &str = "Fingerprint reader unavailable";

pub enum Outcome {
    Match,
    Cancelled,
    /// Carries the message to show.
    Failed(&'static str),
}

/// Verifies `user`'s fingerprint, allowing `max_tries` non-matching scans.
/// `info` shows a status message to the user, `log` records an error.
pub fn verify(user: &str, max_tries: u32, info: &dyn Fn(&str), log: &dyn Fn(&str)) -> Outcome {
    match run(user, max_tries, info) {
        Ok(outcome) => outcome,
        Err(e) => {
            log(&e);
            Outcome::Failed(MSG_UNAVAILABLE)
        }
    }
}

fn dbus_err(what: &str) -> impl FnOnce(dbus::Error) -> String + '_ {
    move |e| format!("fprintd {what}: {}", e.message().unwrap_or("unknown error"))
}

fn run(user: &str, max_tries: u32, info: &dyn Fn(&str)) -> Result<Outcome, String> {
    let conn = Connection::new_system().map_err(dbus_err("connect"))?;

    let manager = conn.with_proxy(FPRINT, MANAGER_PATH, CALL_TIMEOUT);
    let path: dbus::Path<'static> = match manager.method_call(MANAGER, "GetDefaultDevice", ()) {
        Ok((path,)) => path,
        Err(e) if e.name() == Some(ERR_NO_DEVICE) => return Ok(Outcome::Failed(MSG_UNAVAILABLE)),
        Err(e) => return Err(dbus_err("GetDefaultDevice")(e)),
    };

    // If fprintd restarts, our claim is gone and its signals would come from a
    // new unique name we don't trust: give up instead of waiting forever.
    // Registered before GetNameOwner so no change can slip in between.
    let owner_changed = Arc::new(AtomicBool::new(false));
    let flag = owner_changed.clone();
    let mut rule = MatchRule::new_signal("org.freedesktop.DBus", "NameOwnerChanged");
    rule.sender = Some("org.freedesktop.DBus".into());
    conn.add_match(rule, move |(): (), _: &Connection, msg: &Message| {
        if msg.read1::<&str>().is_ok_and(|name| name == FPRINT) {
            flag.store(true, Ordering::SeqCst);
        }
        true
    })
    .map_err(dbus_err("AddMatch"))?;

    // Signals are only trusted from fprintd itself; any client on the system
    // bus can emit a VerifyStatus signal with fprintd's object path.
    let bus = conn.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", CALL_TIMEOUT);
    let (owner,): (String,) = bus
        .method_call("org.freedesktop.DBus", "GetNameOwner", (FPRINT,))
        .map_err(dbus_err("GetNameOwner"))?;

    let device = conn.with_proxy(FPRINT, path.clone(), CALL_TIMEOUT);

    // Check before opening the device, which is the slow part.
    match device.method_call::<(Vec<String>,), _, _, _>(DEVICE, "ListEnrolledFingers", (user,)) {
        Ok((fingers,)) if !fingers.is_empty() => {}
        Ok(_) => return Ok(Outcome::Failed(MSG_NO_PRINTS)),
        Err(e) if e.name() == Some(ERR_NO_PRINTS) => return Ok(Outcome::Failed(MSG_NO_PRINTS)),
        Err(e) => return Err(dbus_err("ListEnrolledFingers")(e)),
    }

    let mut input = InputWatch::open();
    info(MSG_STARTING);
    if !claim(&device, user, &mut input)? {
        return Ok(Outcome::Cancelled);
    }
    let _claim = Claim { conn: &conn, path: &path };

    // fprintd broadcasts VerifyStatus, so other clients' verifications on this
    // device (sudo, a TTY login) are visible too. Only listen once we hold the
    // device: nobody else can verify on it from here on, and fprintd's
    // messages arrive in order, so nothing from an earlier session can follow
    // the Claim reply.
    let (tx, rx) = mpsc::channel();
    let mut rule = MatchRule::new_signal(DEVICE, "VerifyStatus");
    rule.path = Some(path.clone());
    conn.add_match(rule, move |(): (), _: &Connection, msg: &Message| {
        if msg.sender().is_some_and(|s| *s == *owner)
            && let Ok((result, done)) = msg.read2::<String, bool>()
        {
            let _ = tx.send((result, done));
        }
        true
    })
    .map_err(dbus_err("AddMatch"))?;

    device
        .method_call::<(), _, _, _>(DEVICE, "VerifyStart", ("any",))
        .map_err(dbus_err("VerifyStart"))?;
    info(MSG_READY);
    let deadline = Instant::now() + SCAN_TIMEOUT;

    let mut tries = 0;
    loop {
        conn.process(POLL).map_err(dbus_err("process"))?;
        if owner_changed.load(Ordering::SeqCst) {
            return Err("fprintd restarted during the scan".into());
        }
        if input.pressed() || Instant::now() >= deadline {
            stop(&device);
            return Ok(Outcome::Cancelled);
        }
        while let Ok((result, done)) = rx.try_recv() {
            match result.as_str() {
                "verify-match" => {
                    stop(&device);
                    return Ok(Outcome::Match);
                }
                "verify-no-match" => {
                    tries += 1;
                    if tries >= max_tries {
                        stop(&device);
                        return Ok(Outcome::Failed(MSG_FAILED));
                    }
                    info(MSG_NO_MATCH);
                    restart(&device)?;
                }
                "verify-retry-scan" | "verify-swipe-too-short" | "verify-finger-not-centered"
                | "verify-remove-and-retry" => {
                    info(MSG_RESCAN);
                    if done {
                        restart(&device)?;
                    }
                }
                other => {
                    stop(&device);
                    return Err(format!("fprintd verify ended with {other}"));
                }
            }
        }
    }
}

/// Claims the device. Returns false if a key was pressed while waiting for a
/// previous login to let go of it.
fn claim(device: &Proxy<&Connection>, user: &str, input: &mut InputWatch) -> Result<bool, String> {
    let deadline = Instant::now() + CLAIM_RETRY;
    loop {
        match device.method_call::<(), _, _, _>(DEVICE, "Claim", (user,)) {
            Ok(()) => return Ok(true),
            Err(e) if e.name() == Some(ERR_IN_USE) && Instant::now() < deadline => {
                if input.pressed() {
                    return Ok(false);
                }
                thread::sleep(Duration::from_millis(500));
            }
            Err(e) => return Err(dbus_err("Claim")(e)),
        }
    }
}

fn stop(device: &Proxy<&Connection>) {
    let _ = device.method_call::<(), _, _, _>(DEVICE, "VerifyStop", ());
}

fn restart(device: &Proxy<&Connection>) -> Result<(), String> {
    stop(device);
    device
        .method_call::<(), _, _, _>(DEVICE, "VerifyStart", ("any",))
        .map_err(dbus_err("VerifyStart"))
}

/// Releases the device when dropped, without waiting for the reply: closing
/// the device can take a few seconds and the login shouldn't wait for it.
struct Claim<'a> {
    conn: &'a Connection,
    path: &'a dbus::Path<'static>,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        use dbus::channel::Sender;
        if let Ok(msg) = Message::new_method_call(FPRINT, self.path, DEVICE, "Release") {
            let _ = self.conn.send(msg);
            self.conn.channel().flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a person at the sensor: `cargo test -- --ignored --nocapture`.
    /// Touch the sensor to match, or press a key to cancel.
    #[test]
    #[ignore]
    fn live_verify() {
        let user = std::env::var("USER").unwrap();
        let outcome = verify(&user, 3, &|m| println!("info: {m}"), &|e| println!("error: {e}"));
        match outcome {
            Outcome::Match => println!("result: match"),
            Outcome::Cancelled => println!("result: cancelled"),
            Outcome::Failed(m) => println!("result: failed ({m})"),
        }
    }
}
