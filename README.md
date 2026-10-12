# pam_tpm_keyring

Fingerprint login for SDDM that also unlocks the GNOME keyring.

A fingerprint login never produces a password, so `pam_gnome_keyring` can't
unlock the login keyring. This module keeps a copy of the login password sealed
to the TPM with `systemd-creds` (bound to PCR 7, the Secure Boot state), and
hands it to `pam_gnome_keyring` after a fingerprint match.

Modes:

- `fingerprint`: asks for the password. A typed password is passed on to
  `pam_unix`. An empty one means "scan a fingerprint": the module verifies it
  through fprintd's D-Bus API and, on a match, sets the unsealed password as
  `PAM_AUTHTOK`. Pressing any key or mouse button cancels the scan, which is
  what lets the greeter switch to password entry instantly (SDDM can't cancel a
  login in progress). Status messages ("Touch the fingerprint sensor", "Not
  recognized, try again", ...) are sent as PAM info messages.
- `seal`: on the password path, after `pam_unix` accepted the password, seal it
  unless the stored copy is already current. Skipped unless Secure Boot is
  enforced.
- `unseal`: for stacks that keep using `pam_fprintd`.
- `allow-locked`: see below.
- `max-tries=N` (default 3), `debug`.

Sealed copies live in `/var/lib/pam-tpm-keyring/<user>.cred` (root only). They
can only be decrypted by this machine's TPM, and only while PCR 7 matches.
fprintd signals are only accepted from fprintd's own bus name.

`fingerprint` unseals the password before it starts a scan. If that fails
(nothing sealed yet, or a firmware or Secure Boot database update changed
PCR 7), it doesn't scan: it sends "Enter your password to unlock the keyring"
and fails, so the greeter asks for the password, and that login reseals it.
With `allow-locked` it scans anyway; the login works, but the keyring stays
locked until the next password login.

## Requirements

- A TPM 2.0 and systemd's `systemd-creds` (sealing is skipped unless Secure
  Boot is enforced).
- fprintd with an enrolled fingerprint.
- Linux-PAM, libdbus, and a Rust toolchain to build.

Tested on Arch Linux with SDDM 0.21, fprintd 1.94 and gnome-keyring 50.

## Security notes

- **What the TPM binding protects against:** copying the sealed file (or the
  whole disk) to another machine. The copy can only be decrypted by this
  machine's TPM, and only while PCR 7 (the Secure Boot policy) matches.
- **What it doesn't:** PCR 7 doesn't cover the kernel, initrd or kernel command
  line. Someone with physical access who can boot this machine into a root
  shell with Secure Boot still on can decrypt it, for example by adding
  `init=/bin/sh` to the kernel command line in the boot loader.
  - Boot a signed unified kernel image (UKI) instead of a bare kernel. With
    Secure Boot on, systemd-stub ignores the command line the boot loader
    passes, and the initrd is covered by the signature. This works with any
    boot loader.
  - Don't leave anything else signed with the same key that can take a
    command line: a signed bare kernel boots with any options and any initrd.
  - It doesn't help if the root file system can be modified offline (taking
    the disk out, or booting another OS with Secure Boot off): whatever runs
    as root at the next normal boot can decrypt it. Full-disk encryption
    closes that.
- **The sealed copy is the login password itself,** so anyone with root on
  the running system can recover it.
- **The TPM never sees the fingerprint.** Whether a fingerprint matched is
  decided by fprintd on the host; the TPM only checks the boot state.
- **Fingerprint attempts don't count toward `pam_faillock`** (the same as
  `pam_fprintd`). They are limited by `max-tries` per login and need a
  physical touch each time.
- `seal` and `unseal` always return `PAM_IGNORE`, so they can't authenticate
  anyone even if configured as `sufficient`. With `unseal` in your own stack,
  keep in mind that every module after it sees the unsealed password in
  `PAM_AUTHTOK`.

## Install

```sh
cargo build --release
sudo install -Dm755 target/release/libpam_tpm_keyring.so /usr/lib/security/pam_tpm_keyring.so
```

## Test without logging out

```sh
sudo install -Dm644 pam.d/pam-tpm-keyring-test /etc/pam.d/pam-tpm-keyring-test
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # type the password: seals
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # press Enter, touch the sensor: unseals
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # press Enter, then any key: cancels
journalctl -b -t pamtester
```

The test service ends with `pam_unix use_first_pass`, so a fingerprint run only
succeeds if the unsealed password is the real one.

`cargo test -- --ignored --nocapture` runs a fingerprint verification against
fprintd directly (no PAM, no TPM).

## Greeter integration

SDDM's greeter can't cancel a login in progress, so a theme that wants
"fingerprint first, password on demand" drives the module like this:

- Start a fingerprint scan by calling `sddm.login(user, "", session)` (an
  empty password).
- Show the PAM info messages (`onInformationMessage`) as the scan status. They
  are the `MSG_*` strings in `src/fingerprint.rs`.
- To switch to password entry, do nothing special: the click or key press
  that switches the UI also cancels the scan, and the login fails with
  "Fingerprint cancelled". Wait for that `loginFailed` before calling
  `sddm.login` with the typed password (SDDM ignores logins while one is
  running).
- Any other `loginFailed` after a scan (no match, no enrolled prints, no
  reader, or "Enter your password to unlock the keyring") means fingerprint
  login isn't possible right now; fall back to the password field and show the
  last message.
- Never submit an empty password from the password field: that starts a scan.

## Enable for SDDM

```sh
sudo cp /etc/pam.d/sddm /etc/pam.d/sddm.orig
sudo install -m644 pam.d/sddm /etc/pam.d/sddm
```

Keep a TTY login (Ctrl+Alt+F3) handy the first time; it uses a different PAM
stack. To revert, `sudo mv /etc/pam.d/sddm.orig /etc/pam.d/sddm`.

`pam.d/sddm` spells out `system-login`'s auth section, so later changes to
`system-auth` don't reach SDDM's auth stack.
