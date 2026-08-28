//! Safe access to the ACPI tables uACPI has mapped.

use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::slice;

use uacpi_sys::{uacpi_table, uacpi_table_find_by_signature, uacpi_table_unref};

use crate::error::{Result, check, check_optional};

/// A table that uACPI keeps mapped for as long as this handle exists.
pub struct Table {
    /// Descriptor uACPI filled in, holding both the mapping and its index.
    raw: uacpi_table,
}

/// Looks up the first table carrying `signature`, for example `c"TPM2"`.
///
/// # Errors
///
/// Fails if uACPI has not been initialized or if the table subsystem reports a
/// problem other than the table being absent, which is reported as [`None`].
pub fn find_table(signature: &CStr) -> Result<Option<Table>> {
    let mut raw = MaybeUninit::<uacpi_table>::uninit();

    // SAFETY: `signature` is NUL-terminated for the duration of the call and
    // `raw` is a live, writable, suitably aligned destination.
    let status = unsafe { uacpi_table_find_by_signature(signature.as_ptr(), raw.as_mut_ptr()) };

    if check_optional(status)?.is_none() {
        return Ok(None);
    }

    // SAFETY: uACPI reported success, which means it filled the descriptor in.
    let raw = unsafe { raw.assume_init() };
    Ok(Some(Table { raw }))
}

impl Table {
    /// The whole table, starting at its `acpi_sdt_hdr` header.
    ///
    /// The length comes from the header, which uACPI validated against the
    /// mapping before handing the table over.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: every member of the descriptor's union aliases the same mapped
        // address, and the mapping outlives `self`.
        let header = unsafe { self.raw.__bindgen_anon_1.hdr };

        // SAFETY: uACPI checked the header before exposing the table, so
        // `length` describes bytes that are mapped and initialized.
        let length = unsafe { (*header).length };

        // SAFETY: as above, `length` bytes from the header are mapped for as long
        // as this handle holds its reference, and nothing hands out a mutable
        // alias to them.
        unsafe { slice::from_raw_parts(header.cast::<u8>(), length as usize) }
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: `raw` is the descriptor uACPI filled in and still holds the
        // reference taken by the lookup; dropping it releases exactly that.
        let _ = check(unsafe { uacpi_table_unref(&raw mut self.raw) });
    }
}
