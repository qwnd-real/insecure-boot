//! Hashing a loaded PE/COFF image the way a measurement of one has to.
//!
//! The digest of an image is not the digest of its bytes. Two fields change when
//! an image is signed or relocated — the optional header's checksum and the
//! certificate table's data directory entry — so both are left out, the headers
//! are hashed up to their declared end, and the sections follow in the order
//! their raw data appears in the file rather than the order the section table
//! lists them. Anything after the last section is hashed too, except the
//! certificate table itself. This is the Authenticode digest the TCG PC Client
//! profile requires for the `EV_EFI_BOOT_SERVICES_*` events.

use alloc::vec::Vec;

use crate::hash::Hasher;
use crate::{Error, Result};

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

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`, a 32-bit optional header.
const OPTIONAL_MAGIC_32: u16 = 0x010b;

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`, a 64-bit optional header.
const OPTIONAL_MAGIC_64: u16 = 0x020b;

/// Offset of `SizeOfHeaders` within either optional header.
const SIZE_OF_HEADERS_AT: usize = 60;

/// Offset of `CheckSum` within either optional header.
const CHECKSUM_AT: usize = 64;

/// Offset of `NumberOfRvaAndSizes` within a 32-bit optional header.
const RVA_COUNT_AT_32: usize = 92;

/// Offset of `NumberOfRvaAndSizes` within a 64-bit optional header.
const RVA_COUNT_AT_64: usize = 108;

/// Index of the certificate table among the data directories.
const CERTIFICATE_INDEX: usize = 4;

/// Length of one data directory entry: an address and a length.
const DIRECTORY_LEN: usize = 2 * size_of::<u32>();

/// Length of one section header.
const SECTION_HEADER_LEN: usize = 40;

/// Offset of `SizeOfRawData` within a section header.
const RAW_SIZE_AT: usize = 16;

/// Offset of `PointerToRawData` within a section header.
const RAW_OFFSET_AT: usize = 20;

/// Adds the whole of `image` to `hasher` in the order and with the omissions a
/// PE/COFF image measurement calls for.
///
/// # Errors
///
/// Fails if `image` is not a PE/COFF image this can parse, or if one of its
/// headers points outside it.
pub fn hash(hasher: &mut Hasher, image: &[u8]) -> Result<()> {
    let headers = headers(image)?;
    let optional = headers.optional;

    // The headers, minus the checksum and the certificate table's directory
    // entry, up to the end the optional header declares for them.
    let checksum = optional + CHECKSUM_AT;
    hasher.update(range(image, 0, checksum)?);

    let headers_end = usize::try_from(u32_at(image, optional + SIZE_OF_HEADERS_AT)?)
        .map_err(|_| Error::MalformedImage)?;
    let mut at = checksum + size_of::<u32>();

    if let Some(certificate) = certificate_directory(image, optional)? {
        hasher.update(between(image, at, certificate)?);
        at = certificate + DIRECTORY_LEN;
    }

    hasher.update(between(image, at, headers_end)?);

    // Then every section's raw data, in the order that data appears rather than
    // the order the section table lists it in.
    let mut covered = headers_end;
    for (offset, len) in sections(image, &headers)? {
        hasher.update(range(image, offset, len)?);
        covered = covered.checked_add(len).ok_or(Error::MalformedImage)?;
    }

    // Finally whatever follows the last section, which is where a signature would
    // sit and so is where the certificate table has to be left out.
    let certificate_len = certificate_len(image, optional)?;
    let end = image
        .len()
        .checked_sub(certificate_len)
        .ok_or(Error::MalformedImage)?;

    if end > covered {
        hasher.update(between(image, covered, end)?);
    }

    Ok(())
}

/// Where the two headers an image's layout is described by begin.
struct Headers {
    /// Offset of the COFF file header.
    coff: usize,
    /// Offset of the optional header, which follows the COFF file header.
    optional: usize,
}

/// Locates an image's headers, and checks that they are the ones this can read.
fn headers(image: &[u8]) -> Result<Headers> {
    if range(image, 0, DOS_MAGIC.len())? != DOS_MAGIC {
        return Err(Error::MalformedImage);
    }

    let pe = offset(image, PE_OFFSET_AT)?;
    if range(image, pe, PE_MAGIC.len())? != PE_MAGIC {
        return Err(Error::MalformedImage);
    }

    let coff = pe + PE_MAGIC.len();
    let optional = coff + COFF_HEADER_LEN;

    match u16_at(image, optional)? {
        OPTIONAL_MAGIC_32 | OPTIONAL_MAGIC_64 => Ok(Headers { coff, optional }),
        _ => Err(Error::MalformedImage),
    }
}

/// Offset of the certificate table's data directory entry, or [`None`] if the
/// image declares fewer data directories than that.
fn certificate_directory(image: &[u8], optional: usize) -> Result<Option<usize>> {
    let count_at = match u16_at(image, optional)? {
        OPTIONAL_MAGIC_32 => RVA_COUNT_AT_32,
        _ => RVA_COUNT_AT_64,
    };

    let count = u32_at(image, optional + count_at)?;
    if usize::try_from(count).unwrap_or(usize::MAX) <= CERTIFICATE_INDEX {
        return Ok(None);
    }

    let directories = optional + count_at + size_of::<u32>();
    Ok(Some(directories + CERTIFICATE_INDEX * DIRECTORY_LEN))
}

/// Length the certificate table declares for itself, or zero if the image has
/// none.
fn certificate_len(image: &[u8], optional: usize) -> Result<usize> {
    match certificate_directory(image, optional)? {
        None => Ok(0),
        Some(at) => offset(image, at + size_of::<u32>()),
    }
}

/// The raw data of every section that has any, as offset and length pairs in the
/// order the data appears in the image.
fn sections(image: &[u8], headers: &Headers) -> Result<Vec<(usize, usize)>> {
    let count = usize::from(u16_at(image, headers.coff + SECTION_COUNT_AT)?);
    let optional_len = usize::from(u16_at(image, headers.coff + OPTIONAL_LEN_AT)?);
    let table = headers.optional + optional_len;

    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let header = table + index * SECTION_HEADER_LEN;
        let len = offset(image, header + RAW_SIZE_AT)?;
        if len == 0 {
            continue;
        }

        sections.push((offset(image, header + RAW_OFFSET_AT)?, len));
    }

    sections.sort_unstable();

    Ok(sections)
}

/// Reads a little-endian `u32` and widens it to an offset or a length.
fn offset(image: &[u8], at: usize) -> Result<usize> {
    usize::try_from(u32_at(image, at)?).map_err(|_| Error::MalformedImage)
}

/// Reads the little-endian `u16` at `at`.
fn u16_at(image: &[u8], at: usize) -> Result<u16> {
    let bytes = range(image, at, size_of::<u16>())?;
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| Error::MalformedImage)?,
    ))
}

/// Reads the little-endian `u32` at `at`.
fn u32_at(image: &[u8], at: usize) -> Result<u32> {
    let bytes = range(image, at, size_of::<u32>())?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::MalformedImage)?,
    ))
}

/// The `len` bytes of `image` at `at`, which have to be inside it.
fn range(image: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(Error::MalformedImage)?;
    image.get(at..end).ok_or(Error::MalformedImage)
}

/// The bytes of `image` from `from` up to `to`, which have to be inside it and in
/// that order.
fn between(image: &[u8], from: usize, to: usize) -> Result<&[u8]> {
    image.get(from..to).ok_or(Error::MalformedImage)
}
