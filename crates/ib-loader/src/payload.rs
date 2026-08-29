//! Mapping and running the payload image by hand.
//!
//! The payload is not signed, so the firmware's `LoadImage` would refuse it
//! under Secure Boot. Instead the loader maps it itself: the PE headers are
//! parsed, `SizeOfImage` bytes are allocated, the headers and every section's
//! raw data are copied in, and the base relocations are applied for the
//! address the allocation landed on.
//!
//! The payload is called the way the firmware calls this loader — its own
//! image handle and the shared system table — so it has no `LoadedImage` of
//! its own: anything in it that reads the image it is running in sees the
//! loader instead.
//!
//! This is the only module in the crate that touches raw memory, and every
//! such place is justified at the block that does it.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ops::Range;
use core::ptr::NonNull;

use uefi::boot::{self, AllocateType, MemoryType, PAGE_SIZE};
use uefi::table::system_table_raw;
use uefi::{Handle, Status, println};

use crate::error::{Error, Result};

/// Signature a DOS header starts with.
const DOS_MAGIC: [u8; 2] = *b"MZ";

/// Offset of the DOS header field naming where the PE header starts.
const PE_OFFSET_AT: usize = 0x3c;

/// Signature a PE header starts with.
const PE_MAGIC: [u8; 4] = *b"PE\0\0";

/// Length of the COFF file header that follows the PE signature.
const COFF_HEADER_LEN: usize = 20;

/// Offset of the section count within the COFF file header.
const SECTION_COUNT_AT: usize = 2;

/// Offset of the optional header's length within the COFF file header.
const OPTIONAL_LEN_AT: usize = 16;

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`; only a 64-bit payload can run here.
const OPTIONAL_MAGIC_64: u16 = 0x020b;

/// Offset of `AddressOfEntryPoint` within a 64-bit optional header.
const ENTRY_AT: usize = 16;

/// Offset of `ImageBase` within a 64-bit optional header.
const IMAGE_BASE_AT: usize = 24;

/// Offset of `SizeOfImage` within a 64-bit optional header.
const SIZE_OF_IMAGE_AT: usize = 56;

/// Offset of `SizeOfHeaders` within a 64-bit optional header.
const SIZE_OF_HEADERS_AT: usize = 60;

/// Offset of `NumberOfRvaAndSizes` within a 64-bit optional header.
const RVA_COUNT_AT: usize = 108;

/// Length of one data directory entry: an address and a length.
const DIRECTORY_LEN: usize = 2 * size_of::<u32>();

/// Index of the base relocations among the data directories.
const RELOCATION_INDEX: usize = 5;

/// Length of one section header.
const SECTION_HEADER_LEN: usize = 40;

/// Offset of `VirtualSize` within a section header.
const VIRTUAL_SIZE_AT: usize = 8;

/// Offset of `VirtualAddress` within a section header.
const VIRTUAL_ADDRESS_AT: usize = 12;

/// Offset of `SizeOfRawData` within a section header.
const RAW_SIZE_AT: usize = 16;

/// Offset of `PointerToRawData` within a section header.
const RAW_OFFSET_AT: usize = 20;

/// Length of the fixed part of one base-relocation block: the page RVA and
/// the block's length.
const RELOCATION_HEADER_LEN: usize = 8;

/// The base relocation type that holds a 64-bit pointer to patch.
const RELOCATION_DIR64: u16 = 10;

/// The base relocation type that carries nothing and is skipped.
const RELOCATION_ABSOLUTE: u16 = 0;

/// The payload's entry point, called the way the firmware calls ours.
type Entry = unsafe extern "efiapi" fn(Handle, *const c_void) -> Status;

/// Maps `pe` into memory, runs its entry point, and frees it again.
///
/// The status the payload returns is reported, but the run is over once
/// control comes back: the chain continues either way.
///
/// # Errors
///
/// Fails if `pe` is not a PE32+ image this can map, if the firmware refuses
/// the allocation, or if the image's relocations point outside it.
pub fn run(pe: &[u8]) -> Result<()> {
    let image = parse(pe)?;
    let base = allocate(&image)?;
    copy(pe, &image, base)?;
    relocate(&image, base)?;

    println!(
        "insecure-boot: entering the payload at {:#018x}",
        entry(base, &image)
    );
    let returned = call(base, &image);

    // SAFETY: the entry point has returned, so the payload no longer holds
    // the allocation, and the page count is the one it was allocated with.
    let freed = unsafe { boot::free_pages(base, image.pages) };
    println!("insecure-boot: the payload returned {returned}");

    freed.map_err(Error::from)
}

/// Everything the mapper needs to know about the image.
struct Image {
    /// The entry point, as an offset from the image's start.
    entry: usize,
    /// The address the image prefers to be mapped at.
    base: u64,
    /// The image's extent in memory.
    size: usize,
    /// How far the headers extend when mapped.
    headers: usize,
    /// The sections to map.
    sections: Vec<Section>,
    /// The base relocation directory, as an offset range within the image.
    relocations: Range<usize>,
    /// The number of pages the image occupies.
    pages: usize,
}

/// One section: where its raw data sits in the file, and where it lands.
struct Section {
    /// Offset of the section's raw data within the file.
    raw: usize,
    /// Length of that raw data.
    raw_len: usize,
    /// Offset the section is mapped at, from the image's start.
    mapped: usize,
    /// The greater of the raw data's length and the section's virtual size.
    mapped_len: usize,
}

/// Parses a PE32+ image's headers into everything mapping it needs.
///
/// # Errors
///
/// Fails if the image is not PE32+, or any of its headers point outside it.
fn parse(pe: &[u8]) -> Result<Image> {
    if bytes(pe, 0, DOS_MAGIC.len())? != DOS_MAGIC {
        return Err(Error::MalformedPayload);
    }

    let signature = u32_at(pe, PE_OFFSET_AT)? as usize;
    if bytes(pe, signature, PE_MAGIC.len())? != PE_MAGIC {
        return Err(Error::MalformedPayload);
    }

    let coff = signature + PE_MAGIC.len();
    let optional = coff + COFF_HEADER_LEN;

    if u16_at(pe, optional)? != OPTIONAL_MAGIC_64 {
        return Err(Error::MalformedPayload);
    }

    let entry = u32_at(pe, optional + ENTRY_AT)? as usize;
    let base = u64_at(pe, optional + IMAGE_BASE_AT)?;
    let size = u32_at(pe, optional + SIZE_OF_IMAGE_AT)? as usize;
    let headers = u32_at(pe, optional + SIZE_OF_HEADERS_AT)? as usize;

    if size == 0 || size < headers || headers > pe.len() || entry >= size {
        return Err(Error::MalformedPayload);
    }

    let directories = optional + RVA_COUNT_AT + size_of::<u32>();

    let mut relocations = Range::default();
    if u32_at(pe, optional + RVA_COUNT_AT)? as usize > RELOCATION_INDEX {
        let at = directories + RELOCATION_INDEX * DIRECTORY_LEN;
        let address = u32_at(pe, at)? as usize;
        let len = u32_at(pe, at + size_of::<u32>())? as usize;

        // The directory is addressed the way the mapped image sees it, and
        // so is only checked against the image's extent here; what it holds
        // is walked once the image is mapped.
        relocations = address..address + len;
        if relocations.end > size {
            return Err(Error::MalformedPayload);
        }
    }

    let section_count = u16_at(pe, coff + SECTION_COUNT_AT)? as usize;
    let optional_len = u16_at(pe, coff + OPTIONAL_LEN_AT)? as usize;
    let table = optional + optional_len;

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header = table + index * SECTION_HEADER_LEN;

        let raw_len = u32_at(pe, header + RAW_SIZE_AT)? as usize;
        if raw_len == 0 {
            continue;
        }

        let raw = u32_at(pe, header + RAW_OFFSET_AT)? as usize;
        bytes(pe, raw, raw_len)?;

        let mapped = u32_at(pe, header + VIRTUAL_ADDRESS_AT)? as usize;
        let virtual_len = u32_at(pe, header + VIRTUAL_SIZE_AT)? as usize;
        let mapped_len = if virtual_len == 0 {
            raw_len
        } else {
            virtual_len
        };
        if mapped + mapped_len > size {
            return Err(Error::MalformedPayload);
        }

        sections.push(Section {
            raw,
            raw_len,
            mapped,
            mapped_len,
        });
    }

    Ok(Image {
        entry,
        base,
        size,
        headers,
        sections,
        relocations,
        pages: size.div_ceil(PAGE_SIZE),
    })
}

/// Allocates the pages the image maps into.
///
/// # Errors
///
/// Fails if the firmware refuses the allocation.
fn allocate(image: &Image) -> Result<NonNull<u8>> {
    boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_CODE, image.pages)
        .map_err(Error::from)
}

/// Copies the image into its allocation, zeroing what the file does not cover.
///
/// # Errors
///
/// Fails if a range the parser accepted turns out not to be in the file,
/// which cannot happen.
fn copy(pe: &[u8], image: &Image, base: NonNull<u8>) -> Result<()> {
    // SAFETY: the allocation is `image.pages` pages, which covers
    // `image.size` bytes, and every range below was checked against both
    // when the image was parsed.
    unsafe {
        let memory = core::slice::from_raw_parts_mut(base.as_ptr(), image.size);

        memory.fill(0);
        memory[..image.headers].copy_from_slice(bytes(pe, 0, image.headers)?);

        for section in &image.sections {
            let len = section.raw_len.min(section.mapped_len);
            let mapped = memory
                .get_mut(section.mapped..section.mapped + len)
                .ok_or(Error::MalformedPayload)?;
            mapped.copy_from_slice(bytes(pe, section.raw, len)?);
        }
    }

    Ok(())
}

/// Applies the image's base relocations for the address it landed on.
///
/// # Errors
///
/// Fails if the relocation directory is malformed, names a type this does not
/// apply, or patches outside the image.
fn relocate(image: &Image, base: NonNull<u8>) -> Result<()> {
    let delta = (base.as_ptr() as u64).wrapping_sub(image.base);
    if delta == 0 || image.relocations.is_empty() {
        return Ok(());
    }

    // SAFETY: the relocation directory was checked to lie inside the
    // allocation, and every patch below is bounds-checked before it happens.
    unsafe {
        let memory = core::slice::from_raw_parts_mut(base.as_ptr(), image.size);

        // The directory is copied out first: reading it and patching the
        // image would otherwise borrow the same memory both ways.
        let directory = memory[image.relocations.clone()].to_vec();

        let mut at = 0;
        while at < directory.len() {
            let block = u32_at(&directory, at + size_of::<u32>())? as usize;
            if block < RELOCATION_HEADER_LEN || at + block > directory.len() {
                return Err(Error::MalformedPayload);
            }

            let page = u32_at(&directory, at)? as usize;
            let entries = at + RELOCATION_HEADER_LEN..at + block;
            let encoded = bytes(&directory, entries.start, entries.len())?;

            for word in encoded.chunks_exact(size_of::<u16>()) {
                let word =
                    u16::from_le_bytes(word.try_into().map_err(|_| Error::MalformedPayload)?);
                let kind = word >> 12;

                match kind {
                    RELOCATION_ABSOLUTE => continue,
                    RELOCATION_DIR64 => {}
                    other => return Err(Error::UnsupportedRelocation(other)),
                }

                let patched = page + usize::from(word & 0x0fff);
                let value = memory
                    .get_mut(patched..patched + size_of::<u64>())
                    .ok_or(Error::MalformedPayload)?;
                let held =
                    u64::from_le_bytes(value.try_into().map_err(|_| Error::MalformedPayload)?);
                value.copy_from_slice(&(held + delta).to_le_bytes());
            }

            at += block;
        }
    }

    Ok(())
}

/// Calls the payload's entry point, and hands back whatever it returns.
fn call(base: NonNull<u8>, image: &Image) -> Status {
    let table =
        system_table_raw().map_or(core::ptr::null(), |table| table.as_ptr().cast::<c_void>());

    // SAFETY: the entry point was checked against the image's extent, and
    // the handle and the system table outlive the call by construction.
    unsafe {
        let entry: Entry = core::mem::transmute(entry(base, image));
        entry(boot::image_handle(), table)
    }
}

/// The address the image's entry point landed on.
fn entry(base: NonNull<u8>, image: &Image) -> usize {
    base.as_ptr() as usize + image.entry
}

/// The `len` bytes of `image` at `at`, which have to be inside it.
fn bytes(image: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(Error::MalformedPayload)?;
    image.get(at..end).ok_or(Error::MalformedPayload)
}

/// Reads the little-endian `u16` at `at`.
fn u16_at(image: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(image, at, size_of::<u16>())?
            .try_into()
            .map_err(|_| Error::MalformedPayload)?,
    ))
}

/// Reads the little-endian `u32` at `at`.
fn u32_at(image: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(image, at, size_of::<u32>())?
            .try_into()
            .map_err(|_| Error::MalformedPayload)?,
    ))
}

/// Reads the little-endian `u64` at `at`.
fn u64_at(image: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(image, at, size_of::<u64>())?
            .try_into()
            .map_err(|_| Error::MalformedPayload)?,
    ))
}
