//! Raw bindings to [uACPI](https://github.com/uACPI/uACPI), built for the UEFI
//! ABI in reduced-hardware mode.
//!
//! The crate exposes the generated declarations unchanged; it deliberately adds
//! no abstraction of its own. Callers must uphold the contracts documented in
//! the upstream headers under `third-party/uacpi/include`, in particular the
//! initialization ordering enforced by `uacpi_initialize`.
//!
//! Linking against this crate creates undefined references to the
//! `uacpi_kernel_*` host primitives, which the consumer must define.

#![no_std]

#[expect(
    missing_docs,
    non_camel_case_types,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn,
    clippy::missing_safety_doc,
    reason = "generated declarations mirror C spelling and carry no docs of their own"
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;
