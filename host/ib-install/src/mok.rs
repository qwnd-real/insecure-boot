//! The machine owner key this run signs with and asks to be enrolled.
//!
//! The key pair lives in the working directory — `mok.key` holds the private
//! key as PKCS#8 DER, `mok.der` the certificate as DER — so that later runs
//! sign with the same key `MokManager` has already been persuaded to trust.
//! Losing either file means a new key and a new enrollment, so a run that
//! finds one without the other refuses to go on rather than silently
//! replacing a key that may already be enrolled.

use std::path::Path;
use std::str::FromStr;

use der::{Decode, Encode};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::sha2::Sha256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use x509_cert::builder::{Builder, CertificateBuilder, profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::EncodePublicKey;
use x509_cert::time::Validity;
use x509_cert::{Certificate, SubjectPublicKeyInfo};

use crate::error::{Error, Result};

/// Password `MokManager` asks for before it enrolls the key.
#[cfg(windows)]
pub const MOK_PASSWORD: &str = "1234";

/// Where the private key is kept, as PKCS#8 DER.
const KEY_PATH: &str = "mok.key";

/// Where the certificate is kept, as DER.
const CERT_PATH: &str = "mok.der";

/// Modulus size of the key pair, in bits.
const KEY_BITS: usize = 2048;

/// How long the certificate stays valid.
/// Ten years, as long as a certificate is worth trusting.
const VALIDITY: std::time::Duration = std::time::Duration::from_hours(87_600);

/// Subject the self-signed certificate carries.
const SUBJECT: &str = "CN=insecure-boot MOK,O=insecure-boot,C=US";

/// The key pair, its certificate, and the parts of the certificate a
/// signature names it by.
pub struct Mok {
    /// The private key everything this run signs with.
    key: RsaPrivateKey,
    /// The certificate as DER, as `MokManager` stores it.
    cert: Vec<u8>,
    /// The certificate's issuer as DER: itself, since it is self-signed.
    issuer: Vec<u8>,
    /// The certificate's serial number.
    serial: SerialNumber,
}

/// Loads the machine owner key, or generates one if the working directory
/// holds neither half of it.
///
/// # Errors
///
/// Fails if the files cannot be read or written, or exactly one of them is
/// there.
pub fn load_or_generate() -> Result<Mok> {
    let key = Path::new(KEY_PATH);
    let cert = Path::new(CERT_PATH);

    match (key.exists(), cert.exists()) {
        (true, true) => {
            let mok = load(key, cert)?;
            println!("ib-install: using the MOK already in {CERT_PATH}");
            Ok(mok)
        }
        (false, false) => {
            let mok = generate(key, cert)?;
            println!("ib-install: generated a new MOK in {CERT_PATH}");
            Ok(mok)
        }
        (true, false) | (false, true) => Err(Error::Missing {
            path: std::path::PathBuf::from(if key.exists() { CERT_PATH } else { KEY_PATH }),
        }),
    }
}

impl Mok {
    /// The private key, ready to sign.
    pub fn signing_key(&self) -> SigningKey<Sha256> {
        SigningKey::<Sha256>::new(self.key.clone())
    }

    /// The certificate as DER, as `MokManager` stores it.
    pub fn cert(&self) -> &[u8] {
        &self.cert
    }

    /// The certificate's issuer as DER, as a signature names its signer by.
    pub fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    /// The certificate's serial number, as a signature names its signer by.
    pub fn serial(&self) -> &SerialNumber {
        &self.serial
    }
}

/// Reads an existing key pair from the working directory.
///
/// # Errors
///
/// Fails if either file cannot be read or parsed.
fn load(key: &Path, cert: &Path) -> Result<Mok> {
    let key = RsaPrivateKey::from_pkcs8_der(&read(key)?)?;
    let bytes = read(cert)?;
    let certificate = Certificate::from_der(&bytes)?;

    Ok(Mok {
        key,
        issuer: certificate.tbs_certificate().issuer().to_der()?,
        serial: certificate.tbs_certificate().serial_number().clone(),
        cert: bytes,
    })
}

/// Generates a key pair and its self-signed certificate, and writes both to
/// the working directory.
///
/// # Errors
///
/// Fails if either half cannot be made or written.
fn generate(key: &Path, cert: &Path) -> Result<Mok> {
    let private = RsaPrivateKey::new(&mut rand::rng(), KEY_BITS)?;
    write(key, private.to_pkcs8_der()?.as_bytes())?;

    let public = RsaPublicKey::from(&private)
        .to_public_key_der()?
        .as_bytes()
        .to_vec();
    let spki = SubjectPublicKeyInfo::from_der(&public)?;

    let profile = profile::cabf::Root::new(false, Name::from_str(SUBJECT)?)?;
    let validity = Validity::from_now(VALIDITY)?;

    let builder = CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, spki)?;
    let certificate = builder.build(&SigningKey::<Sha256>::new(private.clone()))?;
    let bytes = certificate.to_der()?;
    write(cert, &bytes)?;

    Ok(Mok {
        key: private,
        cert: bytes,
        issuer: certificate.tbs_certificate().issuer().to_der()?,
        serial: certificate.tbs_certificate().serial_number().clone(),
    })
}

/// `EFI_CERT_X509_GUID`, naming what a signature list's entries hold.
#[cfg(any(windows, test))]
const X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];

/// Length of the fixed part of an `EFI_SIGNATURE_LIST`.
#[cfg(any(windows, test))]
const LIST_HEADER: usize = 16 + 3 * size_of::<u32>();

/// Length of an `EFI_SIGNATURE_DATA`'s owner GUID.
#[cfg(any(windows, test))]
const OWNER: usize = 16;

/// Reports whether an `MokList` as shim keeps it already carries `cert`.
///
/// The list is a run of `EFI_SIGNATURE_LIST`s; the certificate is in it when
/// an X.509 entry's data is the certificate, byte for byte.
#[cfg(any(windows, test))]
#[must_use]
pub fn already_enrolled(list: &[u8], cert: &[u8]) -> bool {
    let mut at = 0;
    while let Some(header) = list.get(at..at + LIST_HEADER) {
        let list_size = u32::from_le_bytes(header[16..20].try_into().expect("four bytes")) as usize;
        let signature_size =
            u32::from_le_bytes(header[24..28].try_into().expect("four bytes")) as usize;
        if list_size < LIST_HEADER || at + list_size > list.len() {
            return false;
        }

        if header[..16] == X509_GUID && signature_size > OWNER {
            let mut entry = at + LIST_HEADER;
            while entry + signature_size <= at + list_size {
                if &list[entry + OWNER..entry + signature_size] == cert {
                    return true;
                }
                entry += signature_size;
            }
        }

        at += list_size;
    }

    false
}

/// Wraps `cert` the way an `MokNew` variable asks for it: an
/// `EFI_SIGNATURE_LIST` holding one X.509 certificate.
#[cfg(windows)]
#[must_use]
pub fn signature_list(cert: &[u8]) -> Vec<u8> {
    /// The shim lock GUID, as the owner of the key being enrolled: shim 16's,
    /// in the mixed-endian layout an `EFI_GUID` serializes to.
    const OWNER_GUID: [u8; 16] = [
        0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b,
        0x23,
    ];

    let signature = OWNER + cert.len();
    let list = LIST_HEADER + signature;

    let mut bytes = Vec::with_capacity(list);
    bytes.extend_from_slice(&X509_GUID);
    // The three sizes are 32-bit fields; a certificate too large for one
    // would be too large for any variable store to hold anyway.
    bytes.extend_from_slice(&u32::try_from(list).unwrap_or(u32::MAX).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(signature).unwrap_or(u32::MAX).to_le_bytes());
    bytes.extend_from_slice(&OWNER_GUID);
    bytes.extend_from_slice(cert);
    bytes
}

/// Writes the enrollment request, and the password `MokManager` will ask for,
/// unless the key the working directory holds is already enrolled. Returns
/// whether a request was written.
///
/// # Errors
///
/// Fails if the console lacks the privilege firmware variables need, or the
/// firmware refuses either variable.
#[cfg(windows)]
pub fn enroll(mok: &Mok, request: &[u8]) -> Result<bool> {
    windows::enroll(mok, request)
}

/// Writing the enrollment request, on Windows.
#[cfg(windows)]
mod windows {
    use rsa::sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::WindowsProgramming::{
        GetFirmwareEnvironmentVariableW, SetFirmwareEnvironmentVariableExW,
    };

    use super::Mok;
    use crate::error::{Error, Result};
    use crate::mok::MOK_PASSWORD;

    /// The shim lock GUID, which owns the Mok variables, in the string form
    /// the firmware interface takes. Shim 16 renamed it from the pre-16
    /// `605dab50-e046-4900-...` GUID, and a request written under the old one
    /// is invisible to it.
    const SHIM_LOCK: &str = "{605DAB50-E046-4300-ABB6-3DD810DD8B23}";

    /// The EFI global variable GUID, which owns `SecureBoot`, in the string
    /// form the firmware interface takes.
    const EFI_GLOBAL: &str = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

    /// Attributes the Mok variables are written with: the ones mokutil uses.
    const VARIABLE_ATTRIBUTES: u32 = 0x1 | 0x2 | 0x4;

    /// Enables the privilege writing firmware variables needs, which only an
    /// administrator console can hold.
    fn privilege() -> Result<()> {
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
            // SAFETY: as in the `# Safety` section above.
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
        // SAFETY: as in the `# Safety` section above.
        unsafe { close(token) };

        // The call reports success even when the privilege could not be
        // assigned; the error left behind says which happened.
        if granted == 0 || assigned != 0 {
            return Err(Error::NotElevated);
        }

        Ok(())
    }

    /// Writes `MokNew` and `MokAuth`, after making sure this console can.
    pub fn enroll(mok: &Mok, request: &[u8]) -> Result<bool> {
        privilege()?;

        // A list that cannot be read is no reason to hold the request back:
        // writing one for a key already enrolled only costs the user a
        // confirmation, while skipping for the wrong reason would stop the
        // boot from ever being staged.
        if let Some(list) = mok_list()
            && super::already_enrolled(&list, mok.cert())
        {
            println!("ib-install: the MOK in mok.der is already in this machine's MOK list");
            println!("  no enrollment request: shim will run the loader without asking");
            return Ok(false);
        }

        println!("ib-install: the password MokManager will ask for is \"{MOK_PASSWORD}\"");

        set("MokNew", SHIM_LOCK, request)?;

        // MokManager's plain-hash path digests the request and the typed
        // password together, with the password as UTF-16 and no terminator:
        // SHA256(MokNew || "1234" in UTF-16LE).
        let password: Vec<u8> = MOK_PASSWORD
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut auth = Sha256::new();
        auth.update(request);
        auth.update(&password);
        let auth = auth.finalize();

        set("MokAuth", SHIM_LOCK, &auth)?;

        warn_if_no_secure_boot();
        Ok(true)
    }

    /// Warns when Secure Boot is off, because then shim runs the loader
    /// without checking anything and `MokManager` never runs.
    fn warn_if_no_secure_boot() {
        let mut state = [0_u8; 1];
        // SAFETY: `state` is writable for as many bytes as the call is told,
        // and both string arguments are null-terminated strings the call only
        // reads.
        let read = unsafe {
            GetFirmwareEnvironmentVariableW(
                crate::wide("SecureBoot").as_ptr(),
                crate::wide(EFI_GLOBAL).as_ptr(),
                state.as_mut_ptr().cast(),
                u32::try_from(state.len()).unwrap_or(u32::MAX),
            )
        };

        if read == 1 && state[0] == 0 {
            println!(
                "ib-install: Secure Boot is off, so `MokManager` will not ask anything and shim will run the loader as it is"
            );
        }
    }

    /// Reads the `MokList` shim mirrors for the operating system to read.
    ///
    /// The mirror is what the MOK list looked like at the last shim boot;
    /// `MokList` itself carries no runtime-access attribute and cannot be
    /// read from here.
    fn mok_list() -> Option<Vec<u8>> {
        for capacity in [4 * 1024, 16 * 1024, 64 * 1024] {
            let mut buffer = vec![0_u8; capacity];

            // SAFETY: `buffer` is writable for as many bytes as the call is
            // told, and both string arguments are null-terminated strings the
            // call only reads.
            let read = unsafe {
                GetFirmwareEnvironmentVariableW(
                    crate::wide("MokListRT").as_ptr(),
                    crate::wide(SHIM_LOCK).as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                )
            };
            if read != 0 {
                buffer.truncate(usize::try_from(read).unwrap_or(0));
                return Some(buffer);
            }

            // SAFETY: the call only reads the calling thread's last error.
            if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }

        None
    }

    /// Writes one firmware variable.
    fn set(name: &'static str, guid: &str, value: &[u8]) -> Result<()> {
        // SAFETY: `value` is readable for as many bytes as the call is told,
        // and both string arguments are null-terminated strings the call only
        // reads.
        let set = unsafe {
            SetFirmwareEnvironmentVariableExW(
                crate::wide(name).as_ptr(),
                crate::wide(guid).as_ptr(),
                value.as_ptr().cast(),
                u32::try_from(value.len()).unwrap_or(u32::MAX),
                VARIABLE_ATTRIBUTES,
            )
        };

        if set == 0 {
            // SAFETY: the call only reads the calling thread's last error.
            let code = unsafe { GetLastError() };
            return Err(Error::FirmwareVariable { name, code });
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
}

/// Reads a whole file, naming it if that fails.
fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes a whole file, naming it if that fails.
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::{LIST_HEADER, OWNER, X509_GUID, already_enrolled};

    /// Builds one X.509 signature list around `certs`.
    fn list(certs: &[&[u8]]) -> Vec<u8> {
        certs
            .iter()
            .map(|cert| {
                let signature = u32::try_from(OWNER + cert.len()).expect("a test certificate");
                let list = u32::try_from(LIST_HEADER).expect("a constant that fits") + signature;
                let mut bytes = Vec::with_capacity(list as usize);
                bytes.extend_from_slice(&X509_GUID);
                bytes.extend_from_slice(&list.to_le_bytes());
                bytes.extend_from_slice(&0_u32.to_le_bytes());
                bytes.extend_from_slice(&signature.to_le_bytes());
                bytes.extend_from_slice(&[0_u8; OWNER]);
                bytes.extend_from_slice(cert);
                bytes
            })
            .collect::<Vec<_>>()
            .concat()
    }

    #[test]
    fn finds_a_certificate_the_list_carries() {
        let ours = b"a certificate of ours";
        let theirs = b"a certificate of theirs";
        assert!(already_enrolled(&list(&[theirs, ours]), ours));
        assert!(already_enrolled(&list(&[ours]), ours));
    }

    #[test]
    fn misses_a_certificate_the_list_does_not_carry() {
        assert!(!already_enrolled(&list(&[b"another one"]), b"ours"));
        assert!(!already_enrolled(&[], b"ours"));
    }

    #[test]
    fn stops_at_a_malformed_list() {
        let mut broken = list(&[b"ours"]);
        broken.truncate(broken.len() - 1);
        assert!(!already_enrolled(&broken, b"ours"));
    }
}
