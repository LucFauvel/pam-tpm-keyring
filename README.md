# pam_tpm_keyring

Fingerprint login for SDDM that also unlocks the GNOME keyring.

A fingerprint login never produces a password, so `pam_gnome_keyring` can't
unlock the login keyring. With this module, the login keyring's password is a
random key instead of your login password. The key is kept twice, in
`/var/lib/pam-tpm-keyring` (root only):

- `<user>.cred`: sealed to the TPM with `systemd-creds`, bound to PCR 7 (the
  Secure Boot state). Fingerprint logins use this copy.
- `<user>.slot`: encrypted with a key derived from your login password
  (Argon2id, ChaCha20-Poly1305), like a LUKS key slot. Password logins use
  this copy, and it is how the TPM copy gets resealed when PCR 7 changes.

Either way the module hands the key to `pam_gnome_keyring`. Your login
password itself is never stored, so neither copy reveals it.

Modes:

- `fingerprint`: asks for the password. A typed password is passed on to
  `pam_unix`. An empty one means "scan a fingerprint": the module verifies it
  through fprintd's D-Bus API and, on a match, sets the keyring key as
  `PAM_AUTHTOK`. Pressing any key or mouse button cancels the scan, which is
  what lets the greeter switch to password entry instantly (SDDM can't cancel a
  login in progress). Status messages ("Touch the fingerprint sensor", "Not
  recognized, try again", ...) are sent as PAM info messages.
- `seal`: on the password path, after `pam_unix` accepted the password. Opens
  the slot with it, reseals the key to the TPM if the sealed copy is stale
  (only while Secure Boot is enforced), and replaces `PAM_AUTHTOK` with the
  key.
- `unseal`: for stacks that keep using `pam_fprintd`.
- `allow-locked`: see below.
- `max-tries=N` (default 3), `debug`.
- No mode, in the `password` stack: rewraps the key when the login password
  changes.

`fingerprint` unseals the key before it starts a scan. If that fails (a
firmware or Secure Boot database update changed PCR 7), it doesn't scan: it
sends "Enter your password to unlock the keyring" and fails, so the greeter
asks for the password, and that login reseals the key. With `allow-locked` it
scans anyway; the login works, but the keyring stays locked until the next
password login.

Users who haven't run `pam-tpm-keyring setup` get plain fingerprint login,
without the keyring.

fprintd signals are only accepted from fprintd's own bus name.

## Requirements

- A TPM 2.0, Secure Boot, and systemd's `systemd-creds`.
- fprintd with an enrolled fingerprint.
- Linux-PAM, libdbus, and a Rust toolchain to build.

Tested on Arch Linux with SDDM 0.21, fprintd 1.94 and gnome-keyring 50.

## Security notes

- **What a leaked key gives away:** the login keyring, not your login
  password. The slot can be attacked offline by guessing the password, but
  Argon2id (64 MiB, 3 passes) makes that no easier than attacking
  `/etc/shadow`. The keyring file itself, encrypted with the random key, can't
  be attacked that way at all after setup.
- **Delete old copies of `login.keyring`** (backups, snapshots) from before
  setup: they are still encrypted with your login password, under
  gnome-keyring's own key derivation, which is much cheaper to attack than
  Argon2id.
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
- **Root on the running system can recover the key** (and read an unlocked
  keyring from memory anyway).
- **The TPM never sees the fingerprint.** Whether a fingerprint matched is
  decided by fprintd on the host; the TPM only checks the boot state.
- **Fingerprint attempts don't count toward `pam_faillock`** (the same as
  `pam_fprintd`). They are limited by `max-tries` per login and need a
  physical touch each time.
- `seal` and `unseal` always return `PAM_IGNORE`, so they can't authenticate
  anyone even if configured as `sufficient`. Every module after them sees the
  keyring key in `PAM_AUTHTOK`.

## Install

```sh
cargo build --release
sudo install -Dm755 target/release/libpam_tpm_keyring.so /usr/lib/security/pam_tpm_keyring.so
sudo install -Dm755 target/release/pam-tpm-keyring /usr/local/bin/pam-tpm-keyring
sudo install -m644 pam.d/passwd /etc/pam.d/passwd   # Arch's, plus the rewrap line
```

Then, logged in (the keyring daemon has to be running):

```sh
sudo pam-tpm-keyring setup
```

It asks for your login password, generates the key, writes both copies, and
changes the login keyring's password to the key through gnome-keyring's
control socket (the one `pam_gnome_keyring` uses). Running it again generates
a new key.

**After setup, the keyring's own unlock prompt wants the key,** which nobody
knows. Logins through SDDM unlock it. If it ends up locked in a session
started some other way, run `sudo pam-tpm-keyring unlock`.

**Password changes:** `pam.d/passwd` and `pam.d/sddm` rewrap the key with the
new password. A change through any other PAM service is caught at the next
password login, as long as the TPM copy still unseals. If PCR 7 changed as
well, the slot still opens with the old password: `sudo pam-tpm-keyring setup`
asks for it.

## Test without logging out

```sh
sudo install -Dm644 pam.d/pam-tpm-keyring-test /etc/pam.d/pam-tpm-keyring-test
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # type the password: opens the slot
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # press Enter, touch the sensor: unseals
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # press Enter, then any key: cancels
journalctl -b -t pamtester
```

The debug lines in the journal say where the keyring key came from. The test
service doesn't unlock anything; log in through SDDM for that.

`cargo test -- --ignored --nocapture fingerprint` runs a fingerprint
verification against fprintd directly (no PAM, no TPM). `control`'s ignored
test needs a throwaway gnome-keyring-daemon, see `src/control.rs`.

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
