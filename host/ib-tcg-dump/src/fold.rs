//! Folding an event log into the PCR values it produces.
//!
//! A PCR holds `H(previous || digest)` after each extend, starting from a value
//! of zero — except PCR0, whose first byte pattern carries the locality the
//! `TPM2_Startup` that reset it was issued from. Replaying the log through that
//! recurrence is what a dump's expected values are, and what the platform's own
//! PCRs have to agree with.

use ib_tcglog::{Algorithm, PCR_COUNT};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::tcg::{Bank, Record};

/// Whether this tool can compute the hash `algorithm` names.
pub fn supported(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::SHA1 | Algorithm::SHA256 | Algorithm::SHA384 | Algorithm::SHA512
    )
}

/// Folds the records `bank` was measured into, and returns the resulting PCR0-7
/// values in index order.
///
/// Returns [`None`] if the bank's hash is one this tool cannot compute, or if a
/// record that was measured carries no digest of the expected length for the
/// bank, which leaves the fold undefined.
pub fn fold(bank: Bank, records: &[Record], startup_locality: u8) -> Option<Vec<Vec<u8>>> {
    let mut extends = Vec::new();
    for record in records.iter().filter(|record| record.extends_pcr()) {
        extends.push((record.pcr_index, record.digest(bank.algorithm)?));
    }

    replay(bank.algorithm, bank.digest_size, startup_locality, &extends)
}

/// Folds `extends`, each the PCR index of one measurement and the digest it
/// carried, into the PCR0-7 values they produce.
///
/// Returns [`None`] if the hash is one this tool cannot compute, if a digest is
/// not `digest_size` bytes long, or if an extend names a PCR outside PCR0-7.
pub fn replay(
    algorithm: Algorithm,
    digest_size: usize,
    startup_locality: u8,
    extends: &[(u32, &[u8])],
) -> Option<Vec<Vec<u8>>> {
    if !supported(algorithm) {
        return None;
    }

    let mut values: Vec<Vec<u8>> = (0..PCR_COUNT)
        .map(|index| initial(digest_size, index, startup_locality))
        .collect();

    for (pcr_index, digest) in extends {
        let value = values.get_mut(usize::try_from(*pcr_index).ok()?)?;
        if digest.len() != digest_size {
            return None;
        }

        let extended = extend(algorithm, value, digest)?;
        *value = extended;
    }

    Some(values)
}

/// The value PCR `index` holds before anything extends it.
///
/// PCR0 is reset to the locality the `TPM2_Startup` was issued from rather than
/// to zero, which for a digest-wide big-endian value means the locality sits in
/// the last byte.
fn initial(digest_size: usize, index: u32, startup_locality: u8) -> Vec<u8> {
    let mut value = vec![0_u8; digest_size];
    if index == 0
        && let Some(last) = value.last_mut()
    {
        *last = startup_locality;
    }

    value
}

/// Hashes `current` followed by `digest`, the operation `TPM2_PCR_Extend`
/// performs.
fn extend(algorithm: Algorithm, current: &[u8], digest: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        Algorithm::SHA1 => Some(chain::<Sha1>(current, digest)),
        Algorithm::SHA256 => Some(chain::<Sha256>(current, digest)),
        Algorithm::SHA384 => Some(chain::<Sha384>(current, digest)),
        Algorithm::SHA512 => Some(chain::<Sha512>(current, digest)),
        _ => None,
    }
}

/// Hashes two buffers as one message.
fn chain<H: digest::Digest>(current: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(current);
    hasher.update(digest);

    hasher.finalize().to_vec()
}
