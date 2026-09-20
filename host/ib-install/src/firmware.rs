//! The firmware variables the staging talks to, and the probe that decides
//! whether any of it is possible.
//!
//! Every write this run performs, and every write the staged boot performs
//! afterwards, goes through the same variable services. Firmware that
//! protects its runtime variables, shipped as "UEFI Variable Runtime
//! Protection" or "Password Protection of Runtime Variables", refuses those
//! writes, so the staging probes for it before it touches anything: it
//! reads the `Setup` variable and writes it back with zero bytes changed.
//! A refused probe means a refused boot, and the user is told which setting
//! to turn off.

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, GetLastError, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::{
    GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
};

use crate::error::{Error, Result};

/// The firmware variable that holds the platform configuration.
const SETUP: &str = "Setup";

/// The AMI Aptio `Setup` variable's GUID, in the string form the firmware
/// interface takes.
const AMI_SETUP: &str = "{EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9}";

/// The buffer the `Setup` read starts with, doubled until it fits.
const FIRST_CAPACITY: usize = 4 * 1024;

/// The buffer the `Setup` read gives up at. The variable is far smaller on
/// every firmware this is meant for; anything that claims to be larger is
/// not `Setup`, and is not this run's to write back.
const LAST_CAPACITY: usize = 1024 * 1024;

/// Probes whether the firmware accepts variable writes from the operating
/// system, by reading `Setup` and writing it back with zero bytes changed.
///
/// The staged boot writes `Setup` twice, once to flip the TPM UEFI spec
/// version to TCG 1.2 and once to put it back. Firmware that protects its
/// runtime variables refuses those writes, and refuses this one first, so
/// the staging stops here and names the setting to turn off.
///
/// # Errors
///
/// Fails if `Setup` cannot be read in full, or the write-back is refused.
pub fn probe() -> Result<()> {
    privilege()?;

    let (data, attributes) = read_setup()?;

    // SAFETY: `data` is readable for as many bytes as the call is told, and
    // both string arguments are null-terminated strings the call only reads.
    let written = unsafe {
        SetFirmwareEnvironmentVariableExW(
            crate::wide(SETUP).as_ptr(),
            crate::wide(AMI_SETUP).as_ptr(),
            data.as_ptr().cast(),
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            attributes,
        )
    };

    if written == 0 {
        // SAFETY: the call only reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        return Err(Error::VariableProtection { code });
    }

    Ok(())
}

/// Reads the `Setup` variable whole, with the attributes it was written
/// with, so the probe can put both back exactly.
///
/// The read grows its buffer until the firmware says it fits, because a
/// short read would leave the probe writing a shorter `Setup` back, and
/// that variable is not this run's to change.
///
/// # Errors
///
/// Fails if the variable does not exist, or does not fit the largest buffer
/// this is willing to allocate.
fn read_setup() -> Result<(Vec<u8>, u32)> {
    let mut capacity = FIRST_CAPACITY;
    loop {
        let mut buffer = vec![0_u8; capacity];
        let mut attributes = 0_u32;

        // SAFETY: `buffer` is writable for as many bytes as the call is
        // told, `attributes` is a live slot the call fills, and both string
        // arguments are null-terminated strings the call only reads.
        let read = unsafe {
            GetFirmwareEnvironmentVariableExW(
                crate::wide(SETUP).as_ptr(),
                crate::wide(AMI_SETUP).as_ptr(),
                buffer.as_mut_ptr().cast(),
                u32::try_from(capacity).unwrap_or(u32::MAX),
                &raw mut attributes,
            )
        };

        if read != 0 {
            buffer.truncate(usize::try_from(read).unwrap_or(0));
            return Ok((buffer, attributes));
        }

        // SAFETY: the call only reads the calling thread's last error.
        match unsafe { GetLastError() } {
            ERROR_INSUFFICIENT_BUFFER if capacity < LAST_CAPACITY => capacity *= 2,
            ERROR_FILE_NOT_FOUND => return Err(Error::NoSetupVariable),
            code => return Err(Error::SetupUnreadable { code }),
        }
    }
}

/// Enables the privilege writing firmware variables needs, which only an
/// administrator console can hold.
///
/// # Errors
///
/// Fails with [`Error::NotElevated`] when the console does not hold, or
/// cannot be given, the privilege.
pub(crate) fn privilege() -> Result<()> {
    let mut token = std::ptr::null_mut();
    // SAFETY: `token` is a live, uninitialized handle slot the call fills,
    // and the process handle is the one the operating system guarantees.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut token,
        )
    } == 0
    {
        return Err(Error::NotElevated);
    }

    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the privilege name is a null-terminated string the call only
    // reads, and `luid` is a live slot the call fills.
    if unsafe {
        LookupPrivilegeValueW(
            std::ptr::null(),
            crate::wide("SeSystemEnvironmentPrivilege").as_ptr(),
            &raw mut luid,
        )
    } == 0
    {
        // SAFETY: the handle came from `OpenProcessToken` and is closed
        // exactly once.
        unsafe { close(token) };
        return Err(Error::NotElevated);
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `privileges` describes its own length, and the token handle
    // came from the `OpenProcessToken` call above.
    let granted = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &raw const privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    // SAFETY: the call only reads the calling thread's last error.
    let assigned = unsafe { GetLastError() };
    // SAFETY: the handle came from `OpenProcessToken` and is closed exactly
    // once.
    unsafe { close(token) };

    // The call reports success even when the privilege could not be
    // assigned; the error left behind says which happened.
    if granted == 0 || assigned != 0 {
        return Err(Error::NotElevated);
    }

    Ok(())
}

/// Closes a token handle.
///
/// # Safety
///
/// The handle must come from `OpenProcessToken` and must not be closed
/// twice.
unsafe fn close(token: *mut core::ffi::c_void) {
    // SAFETY: as in the `# Safety` section above.
    unsafe { CloseHandle(token) };
}
