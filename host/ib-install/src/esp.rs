//! Mounting the EFI System Partition and staging the boot on it.
//!
//! The ESP is mounted through `mountvol` on a free drive letter, which needs
//! the administrator console the firmware variables already needed. The
//! Windows boot manager is backed up before anything replaces it, and put
//! back if anything goes wrong after that, so a failed staging leaves a
//! machine that still boots. Copies keep everything about the file they copy:
//! `std::fs::copy` keeps the attributes, and the three timestamps are read
//! off the source and set on the target to be sure.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::{FILETIME, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{GetFileTime, GetLogicalDrives, SetFileTime};

use crate::error::{Error, Result};

/// The name this tool is driven through.
const MOUNTVOL: &str = "mountvol";

/// The Windows boot manager, by name: the boot directory is where every path
/// through [`Esp::boot`] already leads.
const BOOT_MANAGER: &str = "bootmgfw.efi";

/// The mounted EFI System Partition.
pub struct Esp {
    /// The drive letter the ESP was mounted on.
    letter: char,
}

/// Mounts the ESP on a free drive letter.
///
/// # Errors
///
/// Fails if no drive letter is free, or `mountvol` refuses.
pub fn mount() -> Result<Esp> {
    let Some(letter) = free_letter() else {
        return Err(Error::NoEsp);
    };

    let mounted = Command::new(MOUNTVOL)
        .arg(format!("{letter}:"))
        .arg("/S")
        .status()
        .map_err(|source| Error::Command {
            program: MOUNTVOL,
            code: source.raw_os_error(),
        })?;

    if !mounted.success() {
        return Err(Error::Command {
            program: MOUNTVOL,
            code: mounted.code(),
        });
    }

    Ok(Esp { letter })
}

impl Esp {
    /// The drive letter the ESP is mounted on.
    pub fn letter(&self) -> char {
        self.letter
    }

    /// Stages the one-shot boot: the dump and the payload in the root, the
    /// boot manager backed up, and the shim chain in its place.
    ///
    /// # Errors
    ///
    /// Fails if any copy fails; after the backup, the boot manager is put
    /// back before the failure is reported.
    pub fn deploy(&self, payload: &Path, signed: &[u8]) -> Result<()> {
        copy(
            Path::new(ib_tcglog::FILE_NAME),
            &self.root(ib_tcglog::FILE_NAME),
        )?;
        copy(payload, &self.root("ib-load.efi"))?;

        let backup = self.backup()?;

        if let Err(error) = self.install(signed) {
            // The restore failing is the louder problem: the machine may not
            // boot. What the restore failed with is beside that point.
            return match copy(&backup, &self.boot(BOOT_MANAGER)) {
                Ok(()) => Err(error),
                Err(_) => Err(Error::Restore {
                    source: Box::new(error),
                }),
            };
        }

        Ok(())
    }

    /// Copies the Windows boot manager to the ESP root, keeping everything
    /// about it.
    ///
    /// # Errors
    ///
    /// Fails if the boot manager is not there, or the copy fails.
    fn backup(&self) -> Result<PathBuf> {
        let from = self.boot(BOOT_MANAGER);
        if !from.exists() {
            return Err(Error::NoBootManager);
        }

        let to = self.root("ib-bootmgfw.efi");
        copy(&from, &to)?;
        Ok(to)
    }

    /// Puts the shim chain where the boot manager was.
    ///
    /// # Errors
    ///
    /// Fails if any of the three files cannot be written.
    fn install(&self, signed: &[u8]) -> Result<()> {
        copy(Path::new("shimx64.efi"), &self.boot(BOOT_MANAGER))?;
        copy(Path::new("mmx64.efi"), &self.boot("mmx64.efi"))?;
        write(&self.boot("grubx64.efi"), signed)
    }

    /// A path in the root of the ESP.
    fn root(&self, name: &str) -> PathBuf {
        Path::new(&format!("{}:\\", self.letter)).join(name)
    }

    /// A path under the Windows boot directory of the ESP.
    fn boot(&self, name: &str) -> PathBuf {
        self.root(r"EFI\Microsoft\Boot").join(name)
    }
}

/// Finds a drive letter nothing is mounted on, looking from `D` upward.
fn free_letter() -> Option<char> {
    // SAFETY: the call takes no pointers and returns a bitmask.
    let mounted = unsafe { GetLogicalDrives() };

    ('D'..='Z').find(|letter| (mounted & (1 << (*letter as u32 - 'A' as u32))) == 0)
}

/// Copies a file, keeping its attributes and all three of its timestamps.
///
/// # Errors
///
/// Fails if the copy fails, or the timestamps cannot be read or set.
fn copy(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to).map_err(|source| Error::Write {
        path: to.to_path_buf(),
        source,
    })?;

    let source = File::open(from).map_err(|source| Error::Read {
        path: from.to_path_buf(),
        source,
    })?;

    let mut creation = zeroed_filetime();
    let mut access = zeroed_filetime();
    let mut modified = zeroed_filetime();

    // SAFETY: the handle is a live file handle the call only reads, and the
    // three timestamps are live slots the call fills.
    if unsafe {
        GetFileTime(
            source.as_raw_handle(),
            &raw mut creation,
            &raw mut access,
            &raw mut modified,
        )
    } == 0
    {
        return Err(Error::Read {
            path: from.to_path_buf(),
            // SAFETY: the call only reads the calling thread's last error.
            source: io::Error::from_raw_os_error(unsafe { GetLastError() }.cast_signed()),
        });
    }

    let target = OpenOptions::new()
        .write(true)
        .open(to)
        .map_err(|source| Error::Write {
            path: to.to_path_buf(),
            source,
        })?;

    // SAFETY: the handle is a live file handle the call only writes through,
    // and the three timestamps have been filled by the read above.
    if unsafe {
        SetFileTime(
            target.as_raw_handle(),
            &raw const creation,
            &raw const access,
            &raw const modified,
        )
    } == 0
    {
        return Err(Error::Write {
            path: to.to_path_buf(),
            // SAFETY: the call only reads the calling thread's last error.
            source: io::Error::from_raw_os_error(unsafe { GetLastError() }.cast_signed()),
        });
    }

    Ok(())
}

/// Writes a file, keeping nothing about what was there.
///
/// # Errors
///
/// Fails if the file cannot be written.
fn write(to: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(to, bytes).map_err(|source| Error::Write {
        path: to.to_path_buf(),
        source,
    })
}

/// A zeroed `FILETIME`, for the slots a read fills.
fn zeroed_filetime() -> FILETIME {
    FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }
}
