//! The `EFI_TCG2_PROTOCOL` interface itself.
//!
//! What firmware and its consumers see is a table of function pointers, so the
//! state those functions work on has to be reachable from the `This` pointer they
//! are handed. [`Instance`] puts the table first and the state straight after it,
//! which makes the address of the one the address of the other.
//!
//! Boot services run one thing at a time, and nothing in here calls back out into
//! a consumer, so no entry point can be entered while another is still running.
//! That is what makes recovering a `&mut` to the state from `This` sound.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::slice;

use ib_tcglog::{Algorithm, Dump};
use ib_tpm_crb::Tpm;
use ib_tpm2::{BANK_COUNT_MAX, capability, pcr};
use uefi::Status;
use uefi_raw::Boolean;
use uefi_raw::protocol::tcg::v2::{
    Tcg2BootServiceCapability, Tcg2EventLogBitmap, Tcg2EventLogFormat, Tcg2HashAlgorithmBitmap,
    Tcg2HashLogExtendEventFlags, Tcg2Protocol, Tcg2Version,
};

use crate::final_events::FinalEvents;
use crate::hash::Hasher;
use crate::log::{self, Log};
use crate::{Error, Result, pecoff};

/// Highest PCR a measurement made through this protocol may name.
const MAX_PCR_INDEX: u32 = 23;

/// One past the highest PCR the replay fills, so the highest one it owns.
const REPLAYED_PCR_COUNT: u32 = ib_tcglog::PCR_COUNT;

/// Revision of the protocol and of its capability structure that this implements.
const VERSION: Tcg2Version = Tcg2Version { major: 1, minor: 1 };

/// Revision the capability structure reports when only its 1.0 fields fit.
const VERSION_1_0: Tcg2Version = Tcg2Version { major: 1, minor: 0 };

/// Length of the capability structure as revision 1.1 defines it.
const CAPABILITY_LEN: usize = size_of::<Tcg2BootServiceCapability>();

/// Length of the capability structure as revision 1.0 defined it: everything up
/// to and including the manufacturer identifier.
const CAPABILITY_LEN_1_0: usize = CAPABILITY_LEN - 2 * size_of::<u32>();

/// `sizeof(EFI_TCG2_EVENT_HEADER)`, which a caller has to state and this has to
/// agree with.
const EVENT_HEADER_LEN: u32 = 14;

/// `EFI_TCG2_EVENT_HEADER_VERSION`.
const EVENT_HEADER_VERSION: u16 = 1;

/// Offset of an `EFI_TCG2_EVENT`'s own length. The structure is packed, so its
/// fields are read one at a time rather than through a type.
const EVENT_SIZE_AT: usize = 0;

/// Offset of the length the event header states for itself.
const EVENT_HEADER_LEN_AT: usize = EVENT_SIZE_AT + size_of::<u32>();

/// Offset of the event header's revision.
const EVENT_HEADER_VERSION_AT: usize = EVENT_HEADER_LEN_AT + size_of::<u32>();

/// Offset of the PCR the event is measured into.
const EVENT_PCR_INDEX_AT: usize = EVENT_HEADER_VERSION_AT + size_of::<u16>();

/// Offset of the event type.
const EVENT_TYPE_AT: usize = EVENT_PCR_INDEX_AT + size_of::<u32>();

/// Offset of the event data, which is everything after the header.
const EVENT_DATA_AT: usize = EVENT_TYPE_AT + size_of::<u32>();

/// A digest slot that has not been filled in yet.
const NO_DIGEST: ib_tpm2::Digest<'static> = ib_tpm2::Digest {
    algorithm: Algorithm::from_id(0),
    bytes: &[],
};

/// The protocol table, and everything its functions work on.
#[repr(C)]
pub struct Instance {
    /// The table consumers call through. It has to come first: an entry point is
    /// handed a pointer to it and casts that straight back to this type.
    protocol: Tcg2Protocol,
    state: State,
}

/// State the protocol's functions share.
struct State {
    tpm: Tpm,
    capability: Tcg2BootServiceCapability,
    banks: [Algorithm; BANK_COUNT_MAX],
    bank_count: usize,
    log: Log,
    final_events: FinalEvents,
    /// Whether the event log has been handed out, after which further records go
    /// to the final events table as well.
    log_taken: bool,
}

impl Instance {
    /// Builds an instance around `tpm`, with a log that starts out as the one
    /// `dump` was taken from, and a final events table of `final_capacity` bytes.
    ///
    /// `headroom` is how much room the log keeps for records measured later.
    ///
    /// # Errors
    ///
    /// Fails if the TPM cannot be questioned, if it has allocated a bank whose
    /// hash this crate cannot compute, or if firmware will not publish the final
    /// events table.
    pub fn new(
        mut tpm: Tpm,
        dump: Option<&Dump<'_>>,
        headroom: usize,
        final_capacity: usize,
    ) -> Result<Self> {
        let mut banks = [Algorithm::from_id(0); BANK_COUNT_MAX];
        let bank_count = allocated(&mut tpm, &mut banks)?;
        let allocated = banks.get(..bank_count).unwrap_or_default();

        if allocated.is_empty() {
            return Err(Error::NoBanks);
        }

        // Refuse now rather than at the first measurement: a bank this cannot hash
        // would be left behind by every event that followed.
        Hasher::new(allocated)?;

        let capability = Tcg2BootServiceCapability {
            size: byte(CAPABILITY_LEN),
            structure_version: VERSION,
            protocol_version: VERSION,
            hash_algorithm_bitmap: supported(),
            supported_event_logs: Tcg2EventLogBitmap::TCG_2,
            tpm_present_flag: u8::from(true),
            max_command_size: half(property(&mut tpm, capability::Property::MAX_COMMAND_SIZE)?),
            max_response_size: half(property(&mut tpm, capability::Property::MAX_RESPONSE_SIZE)?),
            manufacturer_id: property(&mut tpm, capability::Property::MANUFACTURER)?,
            number_of_pcr_banks: word(bank_count),
            active_pcr_banks: bitmap(allocated),
        };

        let log = Log::new(dump, allocated, headroom)?;
        let final_events = FinalEvents::install(final_capacity)?;

        Ok(Self {
            protocol: TABLE,
            state: State {
                tpm,
                capability,
                banks,
                bank_count,
                log,
                final_events,
                log_taken: false,
            },
        })
    }

    /// Address of the table a consumer calls the protocol through.
    ///
    /// The table is the instance's first field, so the two share an address.
    #[must_use]
    pub fn interface(instance: NonNull<Self>) -> *const c_void {
        instance.as_ptr().cast()
    }

    /// The banks the TPM has allocated, which are the ones a measurement extends.
    #[must_use]
    pub fn banks(&self) -> &[Algorithm] {
        self.state
            .banks
            .get(..self.state.bank_count)
            .unwrap_or_default()
    }

    /// Everything the TPM reported about itself.
    #[must_use]
    pub const fn capability(&self) -> &Tcg2BootServiceCapability {
        &self.state.capability
    }

    /// Address of the event log, its length, and the room it keeps for more.
    #[must_use]
    pub fn log(&self) -> (u64, usize, usize) {
        (
            self.state.log.address(),
            self.state.log.len(),
            self.state.log.spare(),
        )
    }

    /// Address of the final events table, the records it holds, and the room it
    /// keeps for more.
    #[must_use]
    pub fn final_events(&self) -> (u64, u64, usize) {
        (
            self.state.final_events.address(),
            self.state.final_events.events(),
            self.state.final_events.spare(),
        )
    }

    /// Takes the instance apart, withdrawing the final events table and handing
    /// back the TPM.
    ///
    /// # Errors
    ///
    /// Fails if firmware refuses to withdraw the final events table.
    pub fn release(self) -> Result<Tpm> {
        self.state.final_events.uninstall()?;

        Ok(self.state.tpm)
    }
}

/// The table every instance is built with. The functions in it are the same for
/// all of them, because the state each works on comes from the pointer it is
/// handed.
const TABLE: Tcg2Protocol = Tcg2Protocol {
    get_capability,
    get_event_log,
    hash_log_extend_event,
    submit_command,
    get_active_pcr_banks,
    set_active_pcr_banks,
    get_result_of_set_active_pcr_banks,
};

/// `EFI_TCG2_PROTOCOL.GetCapability`.
///
/// A caller states in the structure's first field how much room it has, and gets
/// back as much of the structure as fits: all of it, or the fields revision 1.0
/// defined, or nothing but the length it would need.
unsafe extern "efiapi" fn get_capability(
    this: *mut Tcg2Protocol,
    protocol_capability: *mut Tcg2BootServiceCapability,
) -> Status {
    // SAFETY: firmware hands an entry point the table the protocol was installed
    // with, and no other entry point can be running.
    let Some(instance) = (unsafe { instance(this) }) else {
        return Status::INVALID_PARAMETER;
    };

    let Some(out) = NonNull::new(protocol_capability.cast::<u8>()) else {
        return Status::INVALID_PARAMETER;
    };

    // SAFETY: the structure's first field is the length the caller has room for,
    // so at least that one byte is readable.
    let room = usize::from(unsafe { out.read() });

    let mut value = *instance.capability();
    let len = if room >= CAPABILITY_LEN {
        CAPABILITY_LEN
    } else if room >= CAPABILITY_LEN_1_0 {
        value.structure_version = VERSION_1_0;
        value.protocol_version = VERSION_1_0;
        CAPABILITY_LEN_1_0
    } else {
        // SAFETY: as above, the length field itself is there to be written.
        unsafe { out.write(byte(CAPABILITY_LEN)) };
        return Status::BUFFER_TOO_SMALL;
    };

    value.size = byte(len);

    // SAFETY: the caller declared room for `room` bytes and `len` is no larger,
    // `value` is a distinct local of at least `len` bytes, and the two cannot
    // overlap because one of them is on this stack.
    unsafe { ptr::copy_nonoverlapping(ptr::from_ref(&value).cast::<u8>(), out.as_ptr(), len) };

    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.GetEventLog`.
///
/// Handing the log out is what starts the final events table: from here on a
/// record goes to both, because whoever took the log has no reason to read it
/// again.
unsafe extern "efiapi" fn get_event_log(
    this: *mut Tcg2Protocol,
    event_log_format: Tcg2EventLogFormat,
    event_log_location: *mut u64,
    event_log_last_entry: *mut u64,
    event_log_truncated: *mut Boolean,
) -> Status {
    // SAFETY: as in `get_capability`.
    let Some(instance) = (unsafe { instance(this) }) else {
        return Status::INVALID_PARAMETER;
    };

    // Only the crypto-agile format is kept, which is the one the capability
    // structure declares.
    if event_log_format != Tcg2EventLogFormat::TCG_2 || event_log_location.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: the caller passes somewhere to put each of these, and every one is
    // checked for null first because the specification only requires the location.
    unsafe {
        event_log_location.write(instance.state.log.address());

        if !event_log_last_entry.is_null() {
            event_log_last_entry.write(instance.state.log.last_entry());
        }

        if !event_log_truncated.is_null() {
            event_log_truncated.write(Boolean(u8::from(instance.state.log.truncated())));
        }
    }

    instance.state.log_taken = true;

    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.HashLogExtendEvent`.
///
/// The measurement is hashed with every allocated bank, extended into the PCR the
/// caller names, and then recorded — unless the caller asked for an extend and
/// nothing else.
unsafe extern "efiapi" fn hash_log_extend_event(
    this: *mut Tcg2Protocol,
    flags: Tcg2HashLogExtendEventFlags,
    data_to_hash: u64,
    data_to_hash_len: u64,
    event: *const c_void,
) -> Status {
    // SAFETY: as in `get_capability`.
    let Some(instance) = (unsafe { instance(this) }) else {
        return Status::INVALID_PARAMETER;
    };

    if data_to_hash == 0 || event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: an `EFI_TCG2_EVENT` opens with its own length, so a caller that
    // passed one has at least those four bytes there to read.
    let declared = unsafe { slice::from_raw_parts(event.cast::<u8>(), size_of::<u32>()) };
    let Some(len) = le32(declared, EVENT_SIZE_AT).and_then(|size| usize::try_from(size).ok())
    else {
        return Status::INVALID_PARAMETER;
    };

    if len < EVENT_DATA_AT {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: the structure has just declared itself `len` bytes long, and a
    // caller that lied about that would have to be handing over memory it does not
    // own, which is beyond what this can check.
    let event = unsafe { slice::from_raw_parts(event.cast::<u8>(), len) };

    let header_len = le32(event, EVENT_HEADER_LEN_AT);
    let header_version = le16(event, EVENT_HEADER_VERSION_AT);
    let Some(pcr_index) = le32(event, EVENT_PCR_INDEX_AT) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(event_type) = le32(event, EVENT_TYPE_AT) else {
        return Status::INVALID_PARAMETER;
    };

    if header_len != Some(EVENT_HEADER_LEN)
        || header_version != Some(EVENT_HEADER_VERSION)
        || pcr_index > MAX_PCR_INDEX
    {
        return Status::INVALID_PARAMETER;
    }

    // PCRs below `REPLAYED_PCR_COUNT` hold the values the replay left them
    // with, which is what the operating system is meant to find there. A
    // measurement into one of them is answered with success and otherwise
    // dropped, so the replayed state survives whatever measures through this
    // protocol during the boot.
    if pcr_index < REPLAYED_PCR_COUNT {
        return Status::SUCCESS;
    }

    let data = event.get(EVENT_DATA_AT..).unwrap_or_default();

    let Ok(measured_len) = usize::try_from(data_to_hash_len) else {
        return Status::INVALID_PARAMETER;
    };
    let Ok(measured_at) = usize::try_from(data_to_hash) else {
        return Status::INVALID_PARAMETER;
    };

    // SAFETY: the caller states that `measured_len` bytes live at `data_to_hash`
    // and stay put for the call, which is the contract the protocol puts on it.
    let measured = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(measured_at),
            measured_len,
        )
    };

    let banks = instance.state.banks;
    let bank_count = instance.state.bank_count;
    let Ok(mut hasher) = Hasher::new(banks.get(..bank_count).unwrap_or_default()) else {
        return Status::DEVICE_ERROR;
    };

    if flags.contains(Tcg2HashLogExtendEventFlags::PE_COFF_IMAGE) {
        if pecoff::hash(&mut hasher, measured).is_err() {
            return Status::UNSUPPORTED;
        }
    } else {
        hasher.update(measured);
    }

    let digests = hasher.finish();
    let mut carried = [NO_DIGEST; BANK_COUNT_MAX];
    let count = digests.carry(&mut carried);
    let carried = carried.get(..count).unwrap_or_default();

    if let Err(error) = extend(&mut instance.state.tpm, pcr_index, carried) {
        return status(&error);
    }

    if flags.contains(Tcg2HashLogExtendEventFlags::EFI_TCG2_EXTEND_ONLY) {
        return Status::SUCCESS;
    }

    let Ok(entry) = log::event2(pcr_index, event_type, carried, data) else {
        return Status::VOLUME_FULL;
    };

    let logged = instance.state.log.append(&entry);
    let kept = !instance.state.log_taken || instance.state.final_events.append(&entry);

    if logged && kept {
        Status::SUCCESS
    } else {
        Status::VOLUME_FULL
    }
}

/// `EFI_TCG2_PROTOCOL.SubmitCommand`.
unsafe extern "efiapi" fn submit_command(
    this: *mut Tcg2Protocol,
    input_parameter_block_size: u32,
    input_parameter_block: *const u8,
    output_parameter_block_size: u32,
    output_parameter_block: *mut u8,
) -> Status {
    // SAFETY: as in `get_capability`.
    let Some(instance) = (unsafe { instance(this) }) else {
        return Status::INVALID_PARAMETER;
    };

    if input_parameter_block.is_null()
        || output_parameter_block.is_null()
        || input_parameter_block_size == 0
        || output_parameter_block_size == 0
    {
        return Status::INVALID_PARAMETER;
    }

    // The TPM decides what it will accept, and the capability structure is where a
    // caller was told about it.
    let capability = instance.capability();
    if input_parameter_block_size > u32::from(capability.max_command_size)
        || output_parameter_block_size > u32::from(capability.max_response_size)
    {
        return Status::INVALID_PARAMETER;
    }

    let (Ok(command_len), Ok(reply_len)) = (
        usize::try_from(input_parameter_block_size),
        usize::try_from(output_parameter_block_size),
    ) else {
        return Status::INVALID_PARAMETER;
    };

    // SAFETY: the caller states both blocks are that long and stay put for the
    // call, and the two are separate buffers of its own choosing.
    let (command, reply) = unsafe {
        (
            slice::from_raw_parts(input_parameter_block, command_len),
            slice::from_raw_parts_mut(output_parameter_block, reply_len),
        )
    };

    match instance.state.tpm.transmit(command, reply) {
        Ok(_) => Status::SUCCESS,
        Err(error) => status(&Error::from(error)),
    }
}

/// `EFI_TCG2_PROTOCOL.GetActivePcrBanks`.
unsafe extern "efiapi" fn get_active_pcr_banks(
    this: *mut Tcg2Protocol,
    active_pcr_banks: *mut Tcg2HashAlgorithmBitmap,
) -> Status {
    // SAFETY: as in `get_capability`.
    let Some(instance) = (unsafe { instance(this) }) else {
        return Status::INVALID_PARAMETER;
    };

    if active_pcr_banks.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: the caller passes somewhere to put the bitmap, checked above.
    unsafe { active_pcr_banks.write(instance.capability().active_pcr_banks) };

    Status::SUCCESS
}

/// `EFI_TCG2_PROTOCOL.SetActivePcrBanks`.
///
/// Reallocating the PCR banks means `TPM2_PCR_Allocate` and a platform reset, and
/// neither is implemented here, so the request is refused rather than half-made.
unsafe extern "efiapi" fn set_active_pcr_banks(
    _this: *mut Tcg2Protocol,
    _active_pcr_banks: Tcg2HashAlgorithmBitmap,
) -> Status {
    Status::UNSUPPORTED
}

/// `EFI_TCG2_PROTOCOL.GetResultOfSetActivePcrBanks`.
///
/// No reallocation is ever accepted, so there is never a result of one pending.
unsafe extern "efiapi" fn get_result_of_set_active_pcr_banks(
    _this: *mut Tcg2Protocol,
    operation_present: *mut u32,
    response: *mut u32,
) -> Status {
    if operation_present.is_null() || response.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: the caller passes somewhere to put both, checked above.
    unsafe {
        operation_present.write(0);
        response.write(0);
    }

    Status::SUCCESS
}

/// Recovers the instance an entry point was called on.
///
/// # Safety
///
/// `this` has to be the protocol table of a live [`Instance`], which is what
/// firmware hands back to every entry point, and nothing else may refer to that
/// instance while the result is in use.
unsafe fn instance(this: *mut Tcg2Protocol) -> Option<&'static mut Instance> {
    let mut instance = NonNull::new(this.cast::<Instance>())?;

    // SAFETY: the caller guarantees `this` names a live instance nothing else
    // refers to, and the table being the instance's first field makes the cast an
    // identity on the address.
    Some(unsafe { instance.as_mut() })
}

/// Extends `pcr_index` with one digest per bank.
fn extend(tpm: &mut Tpm, pcr_index: u32, digests: &[ib_tpm2::Digest<'_>]) -> Result<()> {
    let mut command = [0_u8; pcr::EXTEND_CAPACITY];
    let mut reply = [0_u8; pcr::REPLY_CAPACITY];

    let len = pcr::extend(&mut command, pcr_index, digests)
        .ok_or(Error::CommandTooLong("TPM2_PCR_Extend"))?;
    let len = tpm.transmit(command.get(..len).unwrap_or_default(), &mut reply)?;

    ib_tpm2::accepted(reply.get(..len).unwrap_or_default())?;

    Ok(())
}

/// Reads the banks the TPM has allocated into `banks`, and reports how many.
fn allocated(tpm: &mut Tpm, banks: &mut [Algorithm]) -> Result<usize> {
    let mut command = [0_u8; capability::COMMAND_CAPACITY];
    let mut reply = [0_u8; capability::REPLY_CAPACITY];

    let len = capability::pcrs(&mut command).ok_or(Error::CommandTooLong("TPM2_GetCapability"))?;
    let len = tpm.transmit(command.get(..len).unwrap_or_default(), &mut reply)?;

    Ok(capability::banks(
        reply.get(..len).unwrap_or_default(),
        banks,
    )?)
}

/// Reads one fixed property of the TPM.
fn property(tpm: &mut Tpm, property: capability::Property) -> Result<u32> {
    let mut command = [0_u8; capability::COMMAND_CAPACITY];
    let mut reply = [0_u8; capability::REPLY_CAPACITY];

    let len = capability::property(&mut command, property)
        .ok_or(Error::CommandTooLong("TPM2_GetCapability"))?;
    let len = tpm.transmit(command.get(..len).unwrap_or_default(), &mut reply)?;

    Ok(capability::value(reply.get(..len).unwrap_or_default())?)
}

/// The hashes this crate can compute, as the capability structure reports them.
fn supported() -> Tcg2HashAlgorithmBitmap {
    Tcg2HashAlgorithmBitmap::SHA1
        | Tcg2HashAlgorithmBitmap::SHA256
        | Tcg2HashAlgorithmBitmap::SHA384
        | Tcg2HashAlgorithmBitmap::SHA512
}

/// `banks` as the capability structure reports them.
fn bitmap(banks: &[Algorithm]) -> Tcg2HashAlgorithmBitmap {
    banks
        .iter()
        .fold(Tcg2HashAlgorithmBitmap::empty(), |bits, bank| {
            bits | bit(*bank)
        })
}

/// The bit the capability structure gives one bank.
fn bit(algorithm: Algorithm) -> Tcg2HashAlgorithmBitmap {
    match algorithm {
        Algorithm::SHA1 => Tcg2HashAlgorithmBitmap::SHA1,
        Algorithm::SHA256 => Tcg2HashAlgorithmBitmap::SHA256,
        Algorithm::SHA384 => Tcg2HashAlgorithmBitmap::SHA384,
        Algorithm::SHA512 => Tcg2HashAlgorithmBitmap::SHA512,
        Algorithm::SM3_256 => Tcg2HashAlgorithmBitmap::SM3_256,
        _ => Tcg2HashAlgorithmBitmap::empty(),
    }
}

/// The status to answer a caller with when something went wrong below the
/// protocol.
fn status(error: &Error) -> Status {
    match error {
        // A reply that did not fit is about the buffer the caller offered rather
        // than about the device, and the protocol has a status for exactly that.
        Error::Tpm(ib_tpm_crb::Error::ResponseTooLong { .. }) => Status::BUFFER_TOO_SMALL,
        _ => Status::DEVICE_ERROR,
    }
}

/// Reads the little-endian `u32` at `at`, or [`None`] past the end.
fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(size_of::<u32>())?;
    Some(u32::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads the little-endian `u16` at `at`, or [`None`] past the end.
fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(size_of::<u16>())?;
    Some(u16::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Narrows a length to the byte the capability structure records it in.
fn byte(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

/// Narrows a size the TPM reported to the half word the capability structure
/// records it in, which only clips a TPM that accepts more than 65535 bytes at
/// once and so only ever understates what it can do.
fn half(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// Narrows a count to the word the capability structure records it in.
fn word(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
