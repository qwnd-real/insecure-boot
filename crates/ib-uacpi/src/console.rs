//! Sink for uACPI's diagnostics.
//!
//! Messages arrive pre-formatted and newline-terminated because the bindings are
//! built without `UACPI_FORMATTED_LOGGING`, so all this has to do is prefix the
//! level and hand the text to the firmware console.

use core::ffi::CStr;
use core::fmt::Write;

use uacpi_sys::{
    UACPI_LOG_DEBUG, UACPI_LOG_ERROR, UACPI_LOG_INFO, UACPI_LOG_TRACE, UACPI_LOG_WARN, uacpi_char,
    uacpi_log_level,
};
use uefi::system;

/// Writes a uACPI diagnostic to the firmware console.
///
/// Output is best-effort: a failed console write has nowhere left to be
/// reported, so it is dropped.
///
/// # Safety
///
/// `text` must point to a NUL-terminated string that stays valid for the
/// duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_log(level: uacpi_log_level, text: *const uacpi_char) {
    // SAFETY: the caller guarantees a NUL-terminated string valid for the call.
    let message = unsafe { CStr::from_ptr(text) };
    let Ok(message) = message.to_str() else {
        return;
    };

    let _ = system::with_stdout(|stdout| {
        writeln!(stdout, "[uacpi {}] {}", label(level), message.trim_end())
    });
}

/// Short name for a uACPI log level.
fn label(level: uacpi_log_level) -> &'static str {
    match level {
        UACPI_LOG_ERROR => "error",
        UACPI_LOG_WARN => "warn",
        UACPI_LOG_INFO => "info",
        UACPI_LOG_TRACE => "trace",
        UACPI_LOG_DEBUG => "debug",
        _ => "?",
    }
}
