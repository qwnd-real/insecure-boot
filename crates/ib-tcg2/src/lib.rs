//! `EFI_TCG2_PROTOCOL` for a TPM 2.0 device behind a Command Response Buffer.
//!
//! Firmware publishes TCG protocols of its own: `EFI_TCG_PROTOCOL`, which only
//! ever speaks SHA-1 and cannot describe a crypto-agile log, and — on firmware
//! that supports TPM 2.0 — an `EFI_TCG2_PROTOCOL` over the log the firmware
//! kept. [`Tcg2::install`] takes both kinds away and puts this one in their
//! place, so that whatever runs next finds one provider, finds the newer one,
//! and finds the log this protocol built rather than a firmware log that holds
//! nothing of this boot.
//!
//! What the protocol hands out is a real event log, not a summary. It starts as
//! the log a [`Dump`] was taken from, reproduced record for record, and grows as
//! consumers measure things through `HashLogExtendEvent`. Once the log has been
//! collected with `GetEventLog` the records that follow also go into the
//! `EFI_TCG2_FINAL_EVENTS_TABLE`, a configuration table entry in memory that
//! outlives boot services, which is how an operating system learns about anything
//! measured after it took the log.

#![no_std]

extern crate alloc;

mod final_events;
mod hash;
mod instance;
mod log;
mod pecoff;

pub use hash::supported;
pub use instance::Instance;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{self, NonNull};

use ib_tcglog::{Algorithm, Dump};
use ib_tpm_crb::Tpm;
use thiserror::Error as Fail;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::Protocol;
use uefi::proto::tcg::{v1, v2};
use uefi::{Guid, Handle, Identify};

/// Room the event log keeps for records measured after it was built.
///
/// This is what the reference implementation reserves for a log area, and one
/// boot measures a few dozen things into it.
const LOG_HEADROOM: usize = 64 * 1024;

/// Size of the final events table, for the same reason.
const FINAL_EVENTS_CAPACITY: usize = 64 * 1024;

/// Result of a protocol operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Why the protocol could not be provided.
#[derive(Debug, Fail)]
pub enum Error {
    /// The TPM has allocated a bank whose hash this crate cannot compute, so every
    /// measurement would leave that bank's PCRs behind.
    #[error("the TPM has a {0} bank, whose hash this cannot compute")]
    UnsupportedBank(Algorithm),

    /// The TPM reports more allocated banks than a TPM 2.0 can have.
    #[error("the TPM reports {0} allocated PCR banks")]
    TooManyBanks(usize),

    /// The TPM reports no allocated PCR bank at all, leaving nothing to measure
    /// into.
    #[error("the TPM reports no allocated PCR bank")]
    NoBanks,

    /// An event carries more than one log record can describe.
    #[error("an event of {0} bytes does not fit an event log record")]
    EventTooLarge(usize),

    /// An image cannot be measured, because it is not a PE/COFF image this can
    /// read.
    #[error("the image is not a PE/COFF image this can measure")]
    MalformedImage,

    /// The dump the log was to start from cannot be read.
    #[error("the replay dump is unusable: {0}")]
    Dump(#[from] ib_tcglog::Error),

    /// The TPM could not be reached.
    #[error("{0}")]
    Tpm(#[from] ib_tpm_crb::Error),

    /// The TPM answered with something that cannot be used.
    #[error("{0}")]
    Reply(#[from] ib_tpm2::ReplyError),

    /// A command did not fit the buffer reserved for it.
    #[error("a {0} command does not fit the buffer reserved for it")]
    CommandTooLong(&'static str),

    /// Firmware refused a boot service this needs.
    #[error("firmware refused a boot service: {0}")]
    Uefi(#[from] uefi::Error),
}

/// The installed protocol, and everything installing it displaced.
///
/// Dropping this leaves the protocol installed, which is what handing control to
/// something else wants; [`Tcg2::uninstall`] is the other way out, for an image
/// that is about to be unloaded and would take its own function pointers with it.
pub struct Tcg2 {
    handle: Handle,
    instance: NonNull<Instance>,
    displacement: Displacement,
    removed: Vec<Displaced>,
}

/// What installing the protocol found and took away.
#[derive(Clone, Copy)]
#[must_use]
pub struct Displacement {
    /// `EFI_TCG_PROTOCOL` interfaces the firmware had installed.
    pub v1_found: usize,
    /// How many of those went away.
    pub v1_removed: usize,
    /// `EFI_TCG2_PROTOCOL` interfaces the firmware had installed, besides the
    /// one installed here.
    pub v2_found: usize,
    /// How many of those went away.
    pub v2_removed: usize,
}

/// A TCG interface that was taken away, and where to put it back.
struct Displaced {
    handle: Handle,
    guid: &'static Guid,
    interface: *const c_void,
}

impl Tcg2 {
    /// Installs the protocol on a handle of its own, and takes away every TCG
    /// interface the firmware had installed — the 1.2 one, and any `EFI_TCG2_PROTOCOL`
    /// besides this one.
    ///
    /// `tpm` becomes the protocol's, and comes back from [`Tcg2::uninstall`]. When
    /// `dump` is given, the event log starts out as the log that dump was taken
    /// from; otherwise it starts as a single specification identifier event
    /// describing the banks the TPM has allocated.
    ///
    /// Removing a firmware interface is not allowed to stop the newer one from
    /// going in, so one that firmware refuses to part with is left where it is and
    /// counted; [`Tcg2::displaced`] reports what happened.
    ///
    /// # Errors
    ///
    /// Fails if the TPM cannot be questioned, if it has allocated a bank whose
    /// hash this crate cannot compute, if the dump cannot be read, or if firmware
    /// refuses to publish either the final events table or the protocol.
    pub fn install(tpm: Tpm, dump: Option<&Dump<'_>>) -> Result<Self> {
        let instance = Instance::new(tpm, dump, LOG_HEADROOM, FINAL_EVENTS_CAPACITY)?;
        let instance = NonNull::from(Box::leak(Box::new(instance)));

        // SAFETY: the interface is the protocol table of an instance that is leaked
        // and so outlives the installation, and the GUID is the one that table
        // implements.
        let handle = unsafe {
            boot::install_protocol_interface(None, &v2::Tcg::GUID, Instance::interface(instance))
        }?;

        let (displacement, removed) = displace(handle);

        Ok(Self {
            handle,
            instance,
            displacement,
            removed,
        })
    }

    /// What the protocol reports about itself and about the log it keeps.
    #[must_use]
    pub fn instance(&self) -> &Instance {
        // SAFETY: the instance is leaked and does not move until `uninstall` takes
        // it apart, and the protocol's own functions only run inside a call a
        // consumer makes, never while this borrow is alive.
        unsafe { self.instance.as_ref() }
    }

    /// The handle the protocol was installed on.
    #[must_use]
    pub const fn handle(&self) -> Handle {
        self.handle
    }

    /// What installing the protocol found, and what it took away.
    pub const fn displaced(&self) -> Displacement {
        self.displacement
    }

    /// Withdraws the protocol, puts back the TCG interfaces that were taken
    /// away, and hands the TPM back.
    ///
    /// # Errors
    ///
    /// Fails if firmware refuses to withdraw the protocol, to restore an interface
    /// or to withdraw the final events table.
    pub fn uninstall(self) -> Result<Tpm> {
        // SAFETY: the interface is the one the protocol was installed with, and the
        // caller undertakes that nothing is still calling through it.
        unsafe {
            boot::uninstall_protocol_interface(
                self.handle,
                &v2::Tcg::GUID,
                Instance::interface(self.instance),
            )
        }?;

        for displaced in &self.removed {
            // SAFETY: the interface is the one firmware had installed on that same
            // handle under that same GUID, and it was only ever taken away, never
            // freed.
            unsafe {
                boot::install_protocol_interface(
                    Some(displaced.handle),
                    displaced.guid,
                    displaced.interface,
                )
            }?;
        }

        // SAFETY: the instance came from `Box::leak`, the protocol that named it is
        // gone, and nothing else refers to it.
        let instance = unsafe { Box::from_raw(self.instance.as_ptr()) };

        instance.release()
    }
}

/// Takes away every TCG interface the firmware installed that is not the one just
/// installed on `ours`, and reports how many there were and which ones went.
fn displace(ours: Handle) -> (Displacement, Vec<Displaced>) {
    let (v1_found, v1_removed, v1) = take::<v1::Tcg>(&v1::Tcg::GUID, None);
    let (v2_found, v2_removed, v2) = take::<v2::Tcg>(&v2::Tcg::GUID, Some(ours));

    let mut removed = v1;
    removed.extend(v2);

    (
        Displacement {
            v1_found,
            v1_removed,
            v2_found,
            v2_removed,
        },
        removed,
    )
}

/// Takes away every interface of kind `P` the firmware installed — skipping
/// `keep`, the one installed here — and reports how many were found and how many
/// went.
fn take<P: Protocol>(guid: &'static Guid, keep: Option<Handle>) -> (usize, usize, Vec<Displaced>) {
    let Ok(handles) = boot::locate_handle_buffer(SearchType::ByProtocol(guid)) else {
        return (0, 0, Vec::new());
    };

    let handles = handles
        .iter()
        .copied()
        .filter(|handle| Some(*handle) != keep)
        .collect::<Vec<_>>();
    let found = handles.len();

    let mut removed = Vec::new();
    for handle in handles {
        let Some(interface) = interface::<P>(handle) else {
            continue;
        };

        // SAFETY: the interface is the one firmware installed on this handle under
        // this GUID. A consumer still holding it would be left with a dangling
        // protocol, which is the point of displacing it, and is why `uninstall`
        // puts it back.
        let removal = unsafe { boot::uninstall_protocol_interface(handle, guid, interface) };

        if removal.is_ok() {
            removed.push(Displaced {
                handle,
                guid,
                interface,
            });
        }
    }

    (found, removed.len(), removed)
}

/// The address a protocol of kind `P` was installed with on `handle`.
fn interface<P: Protocol>(handle: Handle) -> Option<*const c_void> {
    // SAFETY: the protocol is opened only to learn the address it lives at, and the
    // scoped handle closes again at the end of this function without the interface
    // itself ever being called.
    let protocol = unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;

    Some(ptr::from_ref(&*protocol).cast())
}
