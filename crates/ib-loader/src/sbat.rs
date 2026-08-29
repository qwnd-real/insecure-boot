//! The SBAT section shim 15.3 and later require of everything they launch.
//!
//! Shim refuses a second stage that carries no `.sbat` section at all, and
//! revokes ones it carries by component name and generation. The section here
//! claims the minimum generations there are — one for the SBAT mechanism
//! itself and one for this loader — under a name no revocation list will ever
//! name, because nothing but this loader uses it.
//!
//! The section is just data the linker places under the name shim looks up,
//! so nothing in the crate reads it; it is there for the boot.

/// The text the section holds, as the bytes the section is.
///
/// The first line names the SBAT generation this file speaks; every line
/// after it names one component, its generation, and who is behind it. Shim
/// parses this as CSV and refuses the whole section if any column of any
/// line is empty, so every field carries something.
const TEXT: &str = concat!(
    "sbat,1,SBAT Version,sbat,1,",
    "https://github.com/rhboot/shim/blob/main/SBAT_SBAT.md\n",
    "insecure-boot,1,insecure-boot,insecure-boot,1,https://example.com/\n\0",
);

/// The `.sbat` section shim finds this loader's SBAT data in.
#[unsafe(link_section = ".sbat")]
#[used]
static SBAT: [u8; TEXT.len()] = {
    let mut bytes = [0_u8; TEXT.len()];
    let mut at = 0;
    while at < TEXT.len() {
        bytes[at] = TEXT.as_bytes()[at];
        at += 1;
    }
    bytes
};
