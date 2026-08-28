//! Translation of uACPI status codes into a Rust error type.

use core::ffi::CStr;
use core::fmt;

use uacpi_sys::{
    UACPI_STATUS_INTERNAL_ERROR, UACPI_STATUS_NOT_FOUND, UACPI_STATUS_OK,
    UACPI_STATUS_OUT_OF_MEMORY, uacpi_status, uacpi_status_to_string,
};

/// Result of an operation that calls into uACPI.
pub type Result<T> = core::result::Result<T, Error>;

/// Failure reported by a uACPI entry point.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error(uacpi_status);

impl Error {
    /// Raw uACPI status code behind this error.
    #[must_use]
    pub const fn status(self) -> uacpi_status {
        self.0
    }

    /// Whether uACPI reported that the requested object does not exist.
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        self.0 == UACPI_STATUS_NOT_FOUND
    }

    /// Description of the status code, as spelled by uACPI itself.
    #[must_use]
    pub fn message(self) -> &'static str {
        // SAFETY: `uacpi_status_to_string` maps every input, including codes it
        // does not recognise, to a pointer to a NUL-terminated string literal
        // with static storage duration.
        let text = unsafe { CStr::from_ptr(uacpi_status_to_string(self.0)) };
        text.to_str().unwrap_or("unrecognised uACPI status")
    }

    /// uACPI could not allocate an object this crate asked it to create.
    pub(crate) const fn out_of_memory() -> Self {
        Self(UACPI_STATUS_OUT_OF_MEMORY)
    }

    /// uACPI reported success but handed back something the API says it never
    /// should, such as a null pointer in place of a result.
    pub(crate) const fn malformed() -> Self {
        Self(UACPI_STATUS_INTERNAL_ERROR)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uacpi_status {} ({})", self.0, self.message())
    }
}

impl core::error::Error for Error {}

/// Turns a uACPI status code into a [`Result`].
pub(crate) fn check(status: uacpi_status) -> Result<()> {
    if status == UACPI_STATUS_OK {
        Ok(())
    } else {
        Err(Error(status))
    }
}

/// Turns a uACPI status code into a [`Result`], mapping "not found" to [`None`].
pub(crate) fn check_optional(status: uacpi_status) -> Result<Option<()>> {
    match check(status) {
        Ok(()) => Ok(Some(())),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}
