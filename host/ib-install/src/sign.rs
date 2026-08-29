//! Signing a PE image the way shim expects a signed one to be.
//!
//! The digest is the Authenticode digest — not the digest of the file, but of
//! the file with the checksum and the certificate table's directory entry left
//! out and the sections taken in the order their data appears — and it is
//! carried in a PKCS#7 `SignedData` whose content is an `SpcIndirectData`
//! naming that digest. The signature covers the signed attributes rather than
//! the content directly, which is what pesign and sbsign produce and what
//! shim verifies. The finished blob is appended to the image as a
//! `WIN_CERTIFICATE` and pointed at by the certificate table's directory
//! entry, whose address, unlike every other data directory, is a file offset.

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence, Tag, TagNumber, ValueOrd};

use rsa::sha2::{Digest, Sha256};
use rsa::signature::Signer;

use crate::error::{Error, Result};
use crate::mok::Mok;

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

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
const OPTIONAL_MAGIC_32: u16 = 0x010b;

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const OPTIONAL_MAGIC_64: u16 = 0x020b;

/// Offset of `CheckSum` within either optional header.
const CHECKSUM_AT: usize = 64;

/// Offset of `SizeOfHeaders` within either optional header.
const SIZE_OF_HEADERS_AT: usize = 60;

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

/// Length of a section header's name field.
const SECTION_NAME_LEN: usize = 8;

/// Offset of `SizeOfRawData` within a section header.
const RAW_SIZE_AT: usize = 16;

/// Offset of `PointerToRawData` within a section header.
const RAW_OFFSET_AT: usize = 20;

/// `SPC_INDIRECT_DATA_OBJID`, the content type of a signed PE image.
const SPC_INDIRECT_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

/// `SPC_PE_IMAGE_DATA_OBJID`, the content type of the data being measured.
const SPC_PE_IMAGE_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");

/// The minimal `SpcPeImageData` every signer of a PE emits: a `SEQUENCE` of
/// an empty `BIT STRING`. Verifiers match the type it is named by, not what
/// it holds.
const SPC_PE_IMAGE_DATA_VALUE: [u8; 6] = [0x30, 0x04, 0x03, 0x02, 0x00, 0x00];

/// SHA-256, as a digest algorithm.
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `RSA_WITH_SHA256`, as a signature algorithm.
const RSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// `PKCS7_SIGNED_DATA`, the content type of the whole signature.
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// The PKCS#9 attribute naming what kind of content is signed.
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// The PKCS#9 attribute carrying the digest of the content.
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// The explicit NULL every algorithm identifier here carries.
const NULL_PARAMETERS: [u8; 2] = [0x05, 0x00];

/// The tag of the context-specific `[0]` a `SignerInfo` carries a set of
/// attributes under, an `EncapsulatedContentInfo` carries its content, and a
/// `ContentInfo` carries its `SignedData`.
const CONTEXT_ZERO: u8 = 0xa0;

/// The certificate entry's revision, `WIN_CERT_REVISION_2_0`.
const CERTIFICATE_REVISION: u16 = 0x0200;

/// The certificate entry's type, `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
const CERTIFICATE_TYPE: u16 = 0x0002;

/// Length of a `WIN_CERTIFICATE` header, which precedes the PKCS#7 blob.
const WIN_CERTIFICATE_HEADER: usize = 8;

/// Alignment the certificate entry is padded out to.
const CERTIFICATE_ALIGNMENT: usize = 8;

/// `ContentInfo` ::= SEQUENCE { contentType OID, content [0] EXPLICIT }.
#[derive(Sequence)]
struct ContentInfo {
    /// What is signed, and the signature itself.
    content_type: ObjectIdentifier,
    /// The `SignedData`, explicitly tagged.
    content: Any,
}

/// `SignedData` ::= SEQUENCE {
///   version, digestAlgorithms, encapContentInfo,
///   certificates [0] IMPLICIT, signerInfos }.
#[derive(Sequence)]
struct SignedData {
    /// Always 1, the only version PKCS#7 has.
    version: u8,
    /// The one digest algorithm used: SHA-256.
    digest_algorithms: SetOfVec<AlgorithmIdentifier>,
    /// What is signed, and that it is carried here.
    encap_content_info: EncapsulatedContentInfo,
    /// The certificate the key that signed belongs to.
    certificates: Any,
    /// The one signer.
    signer_infos: SetOfVec<SignerInfo>,
}

/// `EncapsulatedContentInfo` ::= SEQUENCE {
///   eContentType OID, eContent [0] EXPLICIT OCTET STRING }.
#[derive(Sequence)]
struct EncapsulatedContentInfo {
    /// What the content is: an `SpcIndirectData`.
    e_content_type: ObjectIdentifier,
    /// The `SpcIndirectData` itself, as an explicitly tagged OCTET STRING.
    e_content: Any,
}

/// `SignerInfo` ::= SEQUENCE {
///   version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm,
///   signature }.
#[derive(Sequence, ValueOrd)]
struct SignerInfo {
    /// Always 1, the only version PKCS#7 has.
    version: u8,
    /// Which certificate signed, by issuer and serial number.
    sid: IssuerAndSerialNumber,
    /// SHA-256.
    digest_algorithm: AlgorithmIdentifier,
    /// The attributes the signature is actually over.
    signed_attrs: Any,
    /// RSA with SHA-256.
    signature_algorithm: AlgorithmIdentifier,
    /// The RSA signature over the DER of the signed attributes.
    signature: OctetString,
}

/// `IssuerAndSerialNumber` ::= SEQUENCE { issuer Name, serialNumber }.
#[derive(Sequence, ValueOrd)]
struct IssuerAndSerialNumber {
    /// The issuer, as the DER of a `Name`.
    issuer: Any,
    /// The serial number the issuer gave the certificate.
    serial_number: Any,
}

/// `AlgorithmIdentifier` ::= SEQUENCE { algorithm OID, parameters }.
///
/// Both algorithms here take no parameters, which DER spells as the explicit
/// NULL the verifiers expect rather than an omission.
#[derive(Clone, Sequence, ValueOrd)]
struct AlgorithmIdentifier {
    /// Which algorithm this is.
    algorithm: ObjectIdentifier,
    /// No parameters, spelled as NULL.
    parameters: Any,
}

/// `Attribute` ::= SEQUENCE { attrType OID, attrValues SET OF }.
#[derive(Sequence, ValueOrd)]
struct Attribute {
    /// Which attribute this is.
    attr_type: ObjectIdentifier,
    /// The attribute's values.
    attr_values: SetOfVec<Any>,
}

/// `SpcIndirectData` ::= SEQUENCE { data, messageDigest }.
#[derive(Sequence)]
struct SpcIndirectData {
    /// What kind of data is measured, and the link that goes with it.
    data: SpcAttributeTypeAndOptionalValue,
    /// The digest of what is measured.
    message_digest: DigestInfo,
}

/// `SpcAttributeTypeAndOptionalValue` ::= SEQUENCE { type OID, value ANY }.
#[derive(Sequence)]
struct SpcAttributeTypeAndOptionalValue {
    /// What kind of data is measured: a PE image.
    r#type: ObjectIdentifier,
    /// A PE image's flags, always none, in the encoding every signer uses.
    value: Any,
}

/// `DigestInfo` ::= SEQUENCE { digestAlgorithm, digest OCTET STRING }.
#[derive(Sequence)]
struct DigestInfo {
    /// SHA-256.
    digest_algorithm: AlgorithmIdentifier,
    /// The digest of the image.
    digest: OctetString,
}

/// Signs `image` with the MOK's key, returning the image with the signature
/// appended and the certificate table pointing at it.
///
/// # Errors
///
/// Fails if `image` is not a PE image this can parse, or already carries a
/// signature.
pub fn sign(image: &[u8], mok: &Mok) -> Result<Vec<u8>> {
    let headers = parse(image)?;

    // The certificate entry lands at the next 8-byte boundary, so the padding
    // this adds is part of what a later verification digests; it has to be in
    // place before the digest is taken.
    let entry = image.len().next_multiple_of(CERTIFICATE_ALIGNMENT);
    let mut padded = vec![0_u8; entry];
    padded[..image.len()].copy_from_slice(image);

    let digest = digest(&padded, &headers)?;
    let signature = signed_data(&digest, mok)?;

    patch(&padded, &headers, &signature)
}

/// Where the two headers an image's layout is described by begin.
struct Headers {
    /// Offset of the optional header, which follows the COFF file header.
    optional: usize,
    /// The offset of the certificate table's directory entry, which the image
    /// has to have room for.
    certificate: usize,
    /// How far the headers extend.
    end: usize,
    /// The sections' raw data, as offset and length pairs.
    sections: Vec<(usize, usize)>,
}

/// Locates an image's headers and sections, and checks that they are the ones
/// this can sign.
///
/// # Errors
///
/// Fails if the image is not a PE image this can parse, or already carries a
/// signature, or has no data directory for a certificate table.
fn parse(image: &[u8]) -> Result<Headers> {
    if bytes(image, 0, DOS_MAGIC.len())? != DOS_MAGIC {
        return Err(Error::MalformedImage);
    }

    let signature = u32_at(image, PE_OFFSET_AT)? as usize;
    if bytes(image, signature, PE_MAGIC.len())? != PE_MAGIC {
        return Err(Error::MalformedImage);
    }

    let coff = signature + PE_MAGIC.len();
    let optional = coff + COFF_HEADER_LEN;

    let rva_count_at = match u16_at(image, optional)? {
        OPTIONAL_MAGIC_32 => RVA_COUNT_AT_32,
        OPTIONAL_MAGIC_64 => RVA_COUNT_AT_64,
        _ => return Err(Error::MalformedImage),
    };

    let end = u32_at(image, optional + SIZE_OF_HEADERS_AT)? as usize;
    if end == 0 || end > image.len() {
        return Err(Error::MalformedImage);
    }

    if u32_at(image, optional + rva_count_at)? as usize <= CERTIFICATE_INDEX {
        return Err(Error::MalformedImage);
    }

    let certificate =
        optional + rva_count_at + size_of::<u32>() + CERTIFICATE_INDEX * DIRECTORY_LEN;
    if u32_at(image, certificate + size_of::<u32>())? != 0 {
        return Err(Error::AlreadySigned);
    }

    let count = u16_at(image, coff + SECTION_COUNT_AT)? as usize;
    let optional_len = u16_at(image, coff + OPTIONAL_LEN_AT)? as usize;
    let table = optional + optional_len;

    let mut sbat = false;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let header = table + index * SECTION_HEADER_LEN;
        if bytes(image, header, SECTION_NAME_LEN)? == b".sbat\0\0\0" {
            sbat = true;
        }

        let len = u32_at(image, header + RAW_SIZE_AT)? as usize;
        if len == 0 {
            continue;
        }

        let offset = u32_at(image, header + RAW_OFFSET_AT)? as usize;
        bytes(image, offset, len)?;
        sections.push((offset, len));
    }

    sections.sort_unstable();

    if !sbat {
        return Err(Error::NoSbat);
    }

    Ok(Headers {
        optional,
        certificate,
        end,
        sections,
    })
}

/// Computes the Authenticode digest of `image`: everything the file holds,
/// except the checksum and the certificate table's directory entry.
///
/// # Errors
///
/// Fails if any range the digest walks falls outside the image, which the
/// parser has already refused.
fn digest(image: &[u8], headers: &Headers) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();

    let checksum = headers.optional + CHECKSUM_AT;
    hasher.update(bytes(image, 0, checksum)?);
    hasher.update(bytes(image, checksum + size_of::<u32>(), headers.end)?);

    let mut covered = headers.end;
    for (offset, len) in &headers.sections {
        let end = offset + len;
        if end > covered {
            hasher.update(bytes(
                image,
                (*offset).max(covered),
                end - (*offset).max(covered),
            )?);
            covered = end;
        }
    }

    hasher.update(bytes(image, covered, image.len() - covered)?);

    Ok(hasher.finalize().into())
}

/// Builds the PKCS#7 blob carrying the digest and the MOK's certificate.
///
/// # Errors
///
/// Fails if any of the DER it assembles cannot be.
fn signed_data(digest: &[u8; 32], mok: &Mok) -> Result<Vec<u8>> {
    let indirect = SpcIndirectData {
        data: SpcAttributeTypeAndOptionalValue {
            r#type: SPC_PE_IMAGE_DATA,
            value: Any::from_der(&SPC_PE_IMAGE_DATA_VALUE)?,
        },
        message_digest: DigestInfo {
            digest_algorithm: AlgorithmIdentifier {
                algorithm: SHA256,
                parameters: Any::from_der(&NULL_PARAMETERS)?,
            },
            digest: OctetString::new(digest.to_vec())?,
        },
    }
    .to_der()?;

    // The signature is over the attributes as a SET OF, with the outer tag
    // rewritten to the context-specific one the SignerInfo carries them
    // under; the bytes signed and the bytes embedded are the same ones.
    let mut attributes = SetOfVec::new();
    attributes.insert(Attribute {
        attr_type: CONTENT_TYPE,
        attr_values: one(Any::from_der(&SPC_INDIRECT_DATA.to_der()?)?)?,
    })?;
    attributes.insert(Attribute {
        attr_type: MESSAGE_DIGEST,
        attr_values: one(Any::from_der(
            &OctetString::new(digest.to_vec())?.to_der()?,
        )?)?,
    })?;

    let signed_attrs = retagged(&attributes.to_der()?, CONTEXT_ZERO);
    let signature = mok.signing_key().try_sign(&signed_attrs)?;
    let signature: Box<[u8]> = signature.into();

    let mut signer_infos = SetOfVec::new();
    signer_infos.insert(SignerInfo {
        version: 1,
        sid: IssuerAndSerialNumber {
            issuer: Any::from_der(mok.issuer())?,
            serial_number: Any::from_der(&mok.serial().to_der()?)?,
        },
        digest_algorithm: AlgorithmIdentifier {
            algorithm: SHA256,
            parameters: Any::from_der(&NULL_PARAMETERS)?,
        },
        signed_attrs: Any::from_der(&signed_attrs)?,
        signature_algorithm: AlgorithmIdentifier {
            algorithm: RSA_WITH_SHA256,
            parameters: Any::from_der(&NULL_PARAMETERS)?,
        },
        signature: OctetString::new(signature.as_ref())?,
    })?;

    let mut certificates = SetOfVec::new();
    certificates.insert(Any::from_der(mok.cert())?)?;

    let signed = SignedData {
        version: 1,
        digest_algorithms: one(AlgorithmIdentifier {
            algorithm: SHA256,
            parameters: Any::from_der(&NULL_PARAMETERS)?,
        })?,
        encap_content_info: EncapsulatedContentInfo {
            e_content_type: SPC_INDIRECT_DATA,
            e_content: explicit(&OctetString::new(indirect)?.to_der()?)?,
        },
        certificates: Any::from_der(&retagged(&certificates.to_der()?, CONTEXT_ZERO))?,
        signer_infos,
    }
    .to_der()?;

    Ok(ContentInfo {
        content_type: SIGNED_DATA,
        content: explicit(&signed)?,
    }
    .to_der()?)
}

/// Appends the certificate entry to the image and points the certificate
/// table's directory entry at it.
///
/// # Errors
///
/// Fails if the table would not fit what was appended, which the arithmetic
/// above rules out.
fn patch(image: &[u8], headers: &Headers, signature: &[u8]) -> Result<Vec<u8>> {
    let entry = image.len().next_multiple_of(CERTIFICATE_ALIGNMENT);

    let mut signed = vec![0_u8; entry];
    signed[..image.len()].copy_from_slice(image);

    let length =
        u32::try_from(WIN_CERTIFICATE_HEADER + signature.len()).map_err(|_| Error::TooLarge)?;
    signed.extend_from_slice(&length.to_le_bytes());
    signed.extend_from_slice(&CERTIFICATE_REVISION.to_le_bytes());
    signed.extend_from_slice(&CERTIFICATE_TYPE.to_le_bytes());
    signed.extend_from_slice(signature);

    let end =
        (entry + WIN_CERTIFICATE_HEADER + signature.len()).next_multiple_of(CERTIFICATE_ALIGNMENT);
    signed.resize(end, 0);

    let address = u32::try_from(entry).map_err(|_| Error::TooLarge)?;
    let table = u32::try_from(end - entry).map_err(|_| Error::TooLarge)?;

    let at = headers.certificate;
    signed[at..at + size_of::<u32>()].copy_from_slice(&address.to_le_bytes());
    signed[at + size_of::<u32>()..at + DIRECTORY_LEN].copy_from_slice(&table.to_le_bytes());

    Ok(signed)
}

/// Wraps the DER of a value in the context-specific `[0]`, explicitly tagged,
/// as an `ANY` a plain field can carry.
///
/// # Errors
///
/// Fails if the wrapper's length cannot be spelled in DER.
fn explicit(der: &[u8]) -> Result<Any> {
    Any::new(
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(0),
        },
        der.to_vec(),
    )
    .map_err(Error::Der)
}

/// Copies DER with its outer tag replaced by `tag`.
fn retagged(der: &[u8], tag: u8) -> Vec<u8> {
    let mut out = der.to_vec();
    out[0] = tag;
    out
}

/// Wraps one value in a single-element `SET OF`.
///
/// # Errors
///
/// Fails if the value cannot be ordered, which a lone element always can.
fn one<T>(value: T) -> Result<SetOfVec<T>>
where
    T: Encode + der::DerOrd,
{
    let mut set = SetOfVec::new();
    set.insert(value)?;
    Ok(set)
}

/// The `len` bytes of `image` at `at`, which have to be inside it.
fn bytes(image: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(Error::MalformedImage)?;
    image.get(at..end).ok_or(Error::MalformedImage)
}

/// Reads the little-endian `u16` at `at`.
fn u16_at(image: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(image, at, size_of::<u16>())?
            .try_into()
            .map_err(|_| Error::MalformedImage)?,
    ))
}

/// Reads the little-endian `u32` at `at`.
fn u32_at(image: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(image, at, size_of::<u32>())?
            .try_into()
            .map_err(|_| Error::MalformedImage)?,
    ))
}
