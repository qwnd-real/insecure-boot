//! Computing the digest of a measurement in every bank the TPM has allocated.
//!
//! A `TPM2_PCR_Extend` extends every allocated bank in one command, and the event
//! log records one digest per bank, so a measurement is hashed with every one of
//! them at once. The hashes run in software rather than through the TPM, because
//! `TPM2_Hash` is limited to what fits in one command and a PE/COFF image is
//! not.

use digest::Digest as _;
use ib_tcglog::Algorithm;
use ib_tpm2::{BANK_COUNT_MAX, DIGEST_LEN_MAX};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{Error, Result};

/// One digest, and the bank whose hash produced it.
#[derive(Clone, Copy, Debug)]
pub struct Digest {
    algorithm: Algorithm,
    len: usize,
    bytes: [u8; DIGEST_LEN_MAX],
}

/// The digests one measurement produced, in bank order.
#[derive(Clone, Copy, Debug)]
pub struct Digests {
    entries: [Digest; BANK_COUNT_MAX],
    len: usize,
}

/// Hashes one measurement with every bank at once.
///
/// The data is handed over in as many pieces as the caller likes, which is what
/// measuring a PE/COFF image needs: its digest covers several ranges of the
/// image and skips the fields that authenticating it would change.
pub struct Hasher {
    banks: [Algorithm; BANK_COUNT_MAX],
    len: usize,
    sha1: Sha1,
    sha256: Sha256,
    sha384: Sha384,
    sha512: Sha512,
}

/// Whether this crate can compute the hash `algorithm` names.
#[must_use]
pub fn supported(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::SHA1 | Algorithm::SHA256 | Algorithm::SHA384 | Algorithm::SHA512
    )
}

impl Hasher {
    /// Starts hashing a measurement for each bank in `banks`.
    ///
    /// # Errors
    ///
    /// Fails if a bank uses a hash this crate cannot compute, because a
    /// measurement that skipped it would leave that bank's PCRs behind.
    pub fn new(banks: &[Algorithm]) -> Result<Self> {
        let mut hasher = Self {
            banks: [Algorithm::from_id(0); BANK_COUNT_MAX],
            len: 0,
            sha1: Sha1::new(),
            sha256: Sha256::new(),
            sha384: Sha384::new(),
            sha512: Sha512::new(),
        };

        for bank in banks {
            if !supported(*bank) {
                return Err(Error::UnsupportedBank(*bank));
            }

            *hasher
                .banks
                .get_mut(hasher.len)
                .ok_or(Error::TooManyBanks(banks.len()))? = *bank;
            hasher.len += 1;
        }

        Ok(hasher)
    }

    /// Adds `data` to every bank's hash.
    pub fn update(&mut self, data: &[u8]) {
        self.sha1.update(data);
        self.sha256.update(data);
        self.sha384.update(data);
        self.sha512.update(data);
    }

    /// Finishes hashing and returns one digest per bank, in bank order.
    #[must_use]
    pub fn finish(self) -> Digests {
        let (banks, len) = (self.banks, self.len);
        let sha1 = self.sha1.finalize();
        let sha256 = self.sha256.finalize();
        let sha384 = self.sha384.finalize();
        let sha512 = self.sha512.finalize();

        let mut digests = Digests {
            entries: [Digest::EMPTY; BANK_COUNT_MAX],
            len: 0,
        };

        for bank in banks.iter().take(len) {
            let digest = match *bank {
                Algorithm::SHA1 => Digest::new(*bank, &sha1),
                Algorithm::SHA256 => Digest::new(*bank, &sha256),
                Algorithm::SHA384 => Digest::new(*bank, &sha384),
                Algorithm::SHA512 => Digest::new(*bank, &sha512),
                // `Hasher::new` refuses every other bank, so this cannot be
                // reached; dropping one is still better than labelling some other
                // hash with it.
                _ => continue,
            };

            if let Some(slot) = digests.entries.get_mut(digests.len) {
                *slot = digest;
                digests.len += 1;
            }
        }

        digests
    }
}

impl Digest {
    /// A digest of no bank at all, which only ever fills unused slots.
    const EMPTY: Self = Self {
        algorithm: Algorithm::from_id(0),
        len: 0,
        bytes: [0; DIGEST_LEN_MAX],
    };

    /// Bank whose hash produced the digest.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The digest itself.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Keeps `bytes`, which no hash this crate computes makes longer than
    /// [`DIGEST_LEN_MAX`].
    fn new(algorithm: Algorithm, bytes: &[u8]) -> Self {
        let mut digest = Self {
            algorithm,
            len: 0,
            bytes: [0; DIGEST_LEN_MAX],
        };

        if let Some(room) = digest.bytes.get_mut(..bytes.len()) {
            room.copy_from_slice(bytes);
            digest.len = bytes.len();
        }

        digest
    }
}

impl Digests {
    /// The digests, in bank order.
    #[must_use]
    pub fn as_slice(&self) -> &[Digest] {
        self.entries.get(..self.len).unwrap_or_default()
    }

    /// Writes the digests into `carried` in the shape a `TPM2_PCR_Extend` and an
    /// event log entry take them in, and reports how many were written.
    pub fn carry<'a>(&'a self, carried: &mut [ib_tpm2::Digest<'a>]) -> usize {
        let mut written = 0;
        for digest in self.as_slice() {
            let Some(slot) = carried.get_mut(written) else {
                break;
            };

            *slot = ib_tpm2::Digest {
                algorithm: digest.algorithm(),
                bytes: digest.bytes(),
            };
            written += 1;
        }

        written
    }
}
