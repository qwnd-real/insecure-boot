//! Reading the platform's event log and its current PCR values.
//!
//! The log is whatever the firmware handed the operating system, byte for byte:
//! on Linux the kernel republishes it through securityfs, and on Windows the TPM
//! Base Services hand back the copy the boot loader kept. Both need
//! administrative rights, because both expose the platform's measured state.
//!
//! Reading the PCRs back out of the running TPM is only ever a cross-check, so
//! it is allowed to be unavailable.

use std::path::Path;

use ib_tcglog::Algorithm;

use crate::error::{Error, Result};

/// An event log and where it was read from.
#[derive(Debug)]
pub struct Log {
    /// The log exactly as the platform published it.
    pub bytes: Vec<u8>,
    /// What to name as the origin when reporting.
    pub origin: String,
}

/// Reads the event log the running platform published.
///
/// # Errors
///
/// Fails if the platform exposes no log, or refuses to hand it over.
pub fn read_log() -> Result<Log> {
    platform::read_log()
}

/// Reads an event log that was saved to `path`.
///
/// # Errors
///
/// Fails if the file cannot be read.
pub fn read_file(path: &Path) -> Result<Log> {
    Ok(Log {
        bytes: read(path)?,
        origin: path.display().to_string(),
    })
}

/// The values the platform's PCR0-7 currently hold in the `algorithm` bank, if
/// the operating system exposes them at all.
#[must_use]
pub fn live_pcrs(algorithm: Algorithm) -> Option<Vec<Vec<u8>>> {
    platform::live_pcrs(algorithm)
}

/// Reads a whole file, naming it if that fails.
fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Reading the log and the PCRs on Linux, where the kernel republishes both.
#[cfg(target_os = "linux")]
mod platform {
    use std::path::Path;
    use std::str;

    use ib_tcglog::{Algorithm, PCR_COUNT};

    use super::{Log, read};
    use crate::error::Result;

    /// Where securityfs republishes the log the firmware handed the kernel.
    const LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

    /// Where sysfs publishes one directory of PCR values per bank.
    const TPM_CLASS: &str = "/sys/class/tpm/tpm0";

    /// Reads the log securityfs publishes.
    pub fn read_log() -> Result<Log> {
        Ok(Log {
            bytes: read(Path::new(LOG_PATH))?,
            origin: LOG_PATH.to_owned(),
        })
    }

    /// Reads the PCR values sysfs publishes for `algorithm`.
    pub fn live_pcrs(algorithm: Algorithm) -> Option<Vec<Vec<u8>>> {
        let bank = bank_directory(algorithm)?;

        (0..PCR_COUNT)
            .map(|index| {
                let path = format!("{TPM_CLASS}/{bank}/{index}");
                unhex(std::fs::read_to_string(path).ok()?.trim())
            })
            .collect()
    }

    /// Directory sysfs publishes the `algorithm` bank under.
    fn bank_directory(algorithm: Algorithm) -> Option<&'static str> {
        match algorithm {
            Algorithm::SHA1 => Some("pcr-sha1"),
            Algorithm::SHA256 => Some("pcr-sha256"),
            Algorithm::SHA384 => Some("pcr-sha384"),
            Algorithm::SHA512 => Some("pcr-sha512"),
            _ => None,
        }
    }

    /// Decodes the hexadecimal digest sysfs writes out.
    fn unhex(text: &str) -> Option<Vec<u8>> {
        if !text.len().is_multiple_of(2) {
            return None;
        }

        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(str::from_utf8(pair).ok()?, 16).ok())
            .collect()
    }
}

/// Reading the log on Windows, where the TPM Base Services keep a copy of it.
#[cfg(windows)]
mod platform {
    use ib_tcglog::Algorithm;
    use windows_sys::Win32::Foundation::TBS_E_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::System::TpmBaseServices::{
        TBS_SUCCESS, TBS_TCGLOG_SRTM_BOOT, Tbsi_Get_TCG_Log_Ex,
    };

    use super::Log;
    use crate::error::{Error, Result};

    /// What to name the log's origin when reporting.
    const ORIGIN: &str = "the TPM Base Services static root of trust boot log";

    /// Function every error here comes out of.
    const CALL: &str = "Tbsi_Get_TCG_Log_Ex";

    /// Buffer the log is asked for in first.
    ///
    /// A firmware boot log runs to tens of kilobytes, so this is enough in
    /// practice; when it is not, the service reports the length it needs and the
    /// request is repeated with exactly that much room.
    const PROBE_CAPACITY: usize = 64 * 1024;

    /// What one attempt at reading the log reported.
    struct Fetched {
        /// Whether the log was written into the buffer.
        complete: bool,
        /// Length the service named for the log.
        len: usize,
    }

    /// Reads the log the platform measured before it handed control to Windows.
    pub fn read_log() -> Result<Log> {
        let mut bytes = vec![0_u8; PROBE_CAPACITY];
        let mut fetched = fetch(&mut bytes)?;

        if !fetched.complete {
            bytes = vec![0_u8; fetched.len];
            fetched = fetch(&mut bytes)?;
        }

        if !fetched.complete || fetched.len > bytes.len() {
            return Err(Error::Tbs {
                call: CALL,
                code: TBS_E_INSUFFICIENT_BUFFER.cast_unsigned(),
            });
        }

        bytes.truncate(fetched.len);

        Ok(Log {
            bytes,
            origin: ORIGIN.to_owned(),
        })
    }

    /// Reading the PCRs back is not implemented here.
    ///
    /// It would mean submitting a `TPM2_PCR_Read` through the service, and the
    /// comparison it feeds is only ever a cross-check: the firmware side of
    /// insecure-boot verifies a replay against the PCRs of the TPM it runs on.
    pub fn live_pcrs(_algorithm: Algorithm) -> Option<Vec<Vec<u8>>> {
        None
    }

    /// Asks the service to write the log into `buffer`.
    fn fetch(buffer: &mut [u8]) -> Result<Fetched> {
        let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);

        // SAFETY: `buffer` is writable for `len` bytes and stays borrowed for the
        // whole call, and `len` points at a live `u32`. Those are the only two
        // pointers the function takes, and it writes no more than `len` bytes
        // before overwriting `len` with the length of the log.
        let code =
            unsafe { Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_BOOT, buffer.as_mut_ptr(), &raw mut len) };

        let complete = code == TBS_SUCCESS;
        if !complete && code.cast_signed() != TBS_E_INSUFFICIENT_BUFFER {
            return Err(Error::Tbs { call: CALL, code });
        }

        Ok(Fetched {
            complete,
            len: usize::try_from(len).unwrap_or(usize::MAX),
        })
    }
}

/// Platforms this tool cannot read by itself.
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use ib_tcglog::Algorithm;

    use super::Log;
    use crate::error::{Error, Result};

    /// Always fails, because there is no interface here to read.
    pub fn read_log() -> Result<Log> {
        Err(Error::UnsupportedPlatform)
    }

    /// Always unavailable, because there is no interface here to read.
    pub fn live_pcrs(_algorithm: Algorithm) -> Option<Vec<Vec<u8>>> {
        None
    }
}
