//! Files under /var/lib/pam-tpm-keyring: a private, root-owned directory whose
//! files are only ever replaced whole.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const STATE_DIR: &str = "/var/lib/pam-tpm-keyring";

pub fn path(name: &str) -> PathBuf {
    Path::new(STATE_DIR).join(name)
}

/// The state directory must be a real directory, owned by root, private.
pub fn check_dir() -> Result<(), String> {
    let meta = fs::symlink_metadata(STATE_DIR).map_err(|e| format!("{STATE_DIR}: {e}"))?;
    if !meta.file_type().is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(format!("{STATE_DIR} must be a root-owned directory with mode 0700"));
    }
    Ok(())
}

/// A new version of a state file, written next to it. It replaces the file on
/// `commit`, and is removed if dropped without one.
pub struct Pending {
    tmp: PathBuf,
    path: PathBuf,
}

impl Pending {
    /// Starts a new version of `name`, without creating the file yet.
    pub fn new(name: &str) -> Result<Self, String> {
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(STATE_DIR)
            .map_err(|e| format!("cannot create {STATE_DIR}: {e}"))?;
        check_dir()?;
        let pending = Pending { tmp: path(&format!(".{name}.tmp")), path: path(name) };
        let _ = fs::remove_file(&pending.tmp);
        Ok(pending)
    }

    /// Starts a new version of `name` holding `data`.
    pub fn write(name: &str, data: &[u8]) -> Result<Self, String> {
        let pending = Pending::new(name)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending.tmp)
            .and_then(|mut file| file.write_all(data).and_then(|_| file.sync_all()))
            .map_err(|e| format!("cannot write {}: {e}", pending.tmp.display()))?;
        Ok(pending)
    }

    /// Where the new version is written before it is committed.
    pub fn tmp_path(&self) -> &Path {
        &self.tmp
    }

    pub fn commit(self) -> Result<(), String> {
        fs::rename(&self.tmp, &self.path).map_err(|e| format!("cannot store {}: {e}", self.path.display()))
        // Drop then finds nothing left to remove.
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp);
    }
}
