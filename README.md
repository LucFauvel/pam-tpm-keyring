# pam_tpm_keyring

Fingerprint login for SDDM that also unlocks the GNOME keyring.

A fingerprint login never produces a password, so `pam_gnome_keyring` can't
unlock the login keyring. With this module, the keyring's password is a random
key instead of your login password, kept twice in `/var/lib/pam-tpm-keyring`
(root only):

- `<user>.cred`: sealed to the TPM with `systemd-creds`, bound to PCR 7 (the
  Secure Boot state). Used by fingerprint logins.
- `<user>.slot`: encrypted with your login password (Argon2id,
  ChaCha20-Poly1305), like a LUKS key slot. Used by password logins, and to
  reseal the TPM copy when PCR 7 changes.

Your login password itself is never stored.

## Modes

- `fingerprint`: asks for the password. A typed one is passed on to
  `pam_unix`; an empty one means "scan a fingerprint" through fprintd, and a
  match sets the keyring key as `PAM_AUTHTOK`. Any key or mouse-button press
  cancels the scan, so the greeter can switch to password entry instantly.
  Status is sent as PAM info messages.
- `seal`: after `pam_unix` accepted the password, opens the slot with it,
  reseals the TPM copy if it's stale, and sets the key as `PAM_AUTHTOK`.
- `unseal`: for stacks that keep using `pam_fprintd`.
- No mode, in the `password` stack: rewraps the key when the password changes.

Options: `allow-locked` (scan even when the key can't be unsealed; the keyring
stays locked), `max-tries=N` (non-matching scans per login, default 3),
`debug`.

If the TPM copy can't be unsealed (a firmware or Secure Boot update changed
PCR 7), `fingerprint` doesn't scan: it sends "Enter your password to unlock the
keyring" and fails, and the next password login reseals the key. Users who
haven't run `pam-tpm-keyring setup` get plain fingerprint login.

## Requirements

A TPM 2.0, Secure Boot, `systemd-creds`, fprintd with an enrolled finger, and
Linux-PAM, libdbus and Rust to build. Tested on Arch Linux with SDDM 0.21,
fprintd 1.94 and gnome-keyring 50.

## Security notes

- **A leaked key** gives away the keyring, not your login password. The slot
  can be attacked offline by guessing the password, but no more cheaply than
  `/etc/shadow`.
- **Delete old copies of `login.keyring`** from before setup: they are
  encrypted with your login password under a much weaker key derivation.
- **The TPM binding** stops a copied disk from being decrypted elsewhere, or
  here after a change to the Secure Boot policy.
- **It doesn't stop** someone with physical access who can boot a root shell
  with Secure Boot on (e.g. `init=/bin/sh`), since PCR 7 doesn't cover the
  kernel command line or initrd. Boot a signed UKI (systemd-stub ignores the
  passed command line under Secure Boot), don't leave other signed kernels
  around, and use full-disk encryption (with encrypted swap) against offline
  tampering.
- **Root on the running system** can recover the key, and read an unlocked
  keyring anyway.
- **The polkit unlock** releases the TPM copy after your own password, in an
  active local session only.
- **The TPM never sees the fingerprint**; fprintd decides the match.
  Fingerprint attempts don't count toward `pam_faillock` (as with
  `pam_fprintd`), but are limited by `max-tries` and need a physical touch.
- `seal` and `unseal` always return `PAM_IGNORE`, so they can't authenticate
  anyone even if misconfigured as `sufficient`.

## Install

```sh
cargo build --release
sudo install -Dm755 target/release/libpam_tpm_keyring.so /usr/lib/security/pam_tpm_keyring.so
sudo install -Dm755 target/release/pam-tpm-keyring /usr/local/bin/pam-tpm-keyring

sudo cp /etc/pam.d/sddm /etc/pam.d/sddm.orig
sudo install -m644 pam.d/sddm /etc/pam.d/sddm
sudo install -m644 pam.d/passwd /etc/pam.d/passwd   # Arch's, plus the rewrap line
```

Keep a TTY login (Ctrl+Alt+F3) handy the first time. To revert,
`sudo mv /etc/pam.d/sddm.orig /etc/pam.d/sddm`. `pam.d/sddm` spells out
`system-login`'s auth section, so later changes to `system-auth` don't reach
it. Your SDDM theme has to drive the scan, see
[Greeter integration](#greeter-integration).

Then, logged in:

```sh
sudo pam-tpm-keyring setup
```

It asks for your login password, writes both copies, and changes the login
keyring's password to the new key through gnome-keyring's control socket. Both
copies are checked before the keyring changes, so a failure leaves the old
password working. Running it again generates a new key.

## Day to day

SDDM logins unlock the keyring, by fingerprint or password.

If it ends up locked anyway, don't use the keyring's own prompt (it wants the
key). Use `sudo pam-tpm-keyring unlock`, or the graphical unlock:

```sh
sudo install -m644 polkit/io.github.lucfauvel.pam-tpm-keyring.policy /usr/share/polkit-1/actions/
sudo install -m755 contrib/unlock-keyring /usr/local/bin/unlock-keyring
install -Dm644 contrib/unlock-keyring.desktop ~/.local/share/applications/unlock-keyring.desktop
```

`unlock-keyring` runs `pkexec pam-tpm-keyring unlock`: your polkit agent asks
for your password, then the TPM copy unlocks the keyring. It needs a running
polkit agent; on Hyprland, for example:

```lua
hl.exec_cmd("systemctl --user start hyprpolkitagent")   -- at startup
hl.bind("SUPER + SHIFT + K", hl.dsp.exec_cmd("/usr/local/bin/unlock-keyring"))
```

If the TPM copy can't be unsealed, use the `sudo` form (it uses the slot) or
log in with your password.

**Password changes** through `passwd` or SDDM rewrap the key. Other services
are caught at the next password login, while the TPM copy still unseals;
otherwise `sudo pam-tpm-keyring setup` asks for the old password.

## Testing

```sh
sudo install -Dm644 pam.d/pam-tpm-keyring-test /etc/pam.d/pam-tpm-keyring-test
sudo pamtester pam-tpm-keyring-test "$USER" authenticate   # password, or Enter then touch/any key
journalctl -b -t pamtester
sudo rm /etc/pam.d/pam-tpm-keyring-test                     # a fingerprint alone passes it
```

The test service unlocks nothing. `cargo test -- --ignored --nocapture
fingerprint` verifies against fprintd directly; `control`'s ignored test needs
a throwaway gnome-keyring-daemon, see `src/control.rs`.

## Greeter integration

SDDM can't cancel a login in progress, so a "fingerprint first" theme does
this:

- Start a scan with `sddm.login(user, "", session)`.
- Show the module's info messages (the `MSG_*` strings in `src/fingerprint.rs`)
  as the status, and ignore any other: SDDM also sends PAM's error
  ("Authentication failure") as an info message just before `loginFailed`.
- To switch to password entry, do nothing special: the click or key press
  cancels the scan with "Fingerprint cancelled". Wait for that `loginFailed`
  before calling `sddm.login` with the typed password.
- Any other failed scan means fall back to the password field and show the
  last message. Keep "Enter your password to unlock the keyring" on screen
  until the password is submitted.
- Never submit an empty password from the password field: that starts a scan.
