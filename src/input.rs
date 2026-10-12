//! Notices key and mouse-button presses, so a fingerprint scan can be
//! abandoned as soon as the user starts typing or clicks something.
//!
//! Only the fact that something was pressed is used; which key it was is
//! ignored.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;

const O_NONBLOCK: i32 = 0o4000;
const EV_KEY: u16 = 1;
const KEY_PRESS: i32 = 1;
/// `struct input_event` on 64-bit Linux: timeval (16), type (2), code (2), value (4).
const EVENT_SIZE: usize = 24;

pub struct InputWatch {
    devices: Vec<File>,
}

impl InputWatch {
    /// Starts watching every input device. Presses before this call don't count.
    pub fn open() -> Self {
        let devices = fs::read_dir("/dev/input")
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("event"))
            .filter_map(|entry| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NONBLOCK)
                    .open(entry.path())
                    .ok()
            })
            .collect();
        InputWatch { devices }
    }

    /// True if a key or button was pressed since the last call.
    pub fn pressed(&mut self) -> bool {
        let mut pressed = false;
        let mut buf = [0u8; EVENT_SIZE * 64];
        for device in &mut self.devices {
            loop {
                match device.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => pressed |= buf[..n].chunks_exact(EVENT_SIZE).any(is_press),
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    // WouldBlock (nothing queued), or the device went away.
                    Err(_) => break,
                }
            }
        }
        pressed
    }
}

fn is_press(event: &[u8]) -> bool {
    let kind = u16::from_ne_bytes([event[16], event[17]]);
    let value = i32::from_ne_bytes([event[20], event[21], event[22], event[23]]);
    kind == EV_KEY && value == KEY_PRESS
}
