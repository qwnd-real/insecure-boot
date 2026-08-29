//! Restoring the Windows boot manager and handing control to it.
//!
//! The host tool replaces `bootmgfw.efi` with a shim before this loader runs,
//! and stages the original in the root of the boot volume. Putting it back —
//! with the timestamps and attributes it carried — is the first thing the
//! loader does, so that a failure anywhere later still leaves a machine that
//! boots Windows.
//!
//! The restored boot manager is then loaded from its own path. It reads its
//! device path to find the BCD store next to itself, so loading it from the
//! path rather than from the bytes it holds is what makes it work.

use uefi::boot::{self, LoadImageSource};
use uefi::println;
use uefi::proto::BootPolicy;

use crate::error::{Error, Result};
use crate::fs::{self, Volume};

/// Where the firmware expects the Windows boot manager.
pub const PATH: &str = r"\EFI\Microsoft\Boot\bootmgfw.efi";

/// Where the host tool stages the original boot manager.
pub const BACKUP: &str = r"\ib-bootmgfw.efi";

/// Where the shim looks for `MokManager`, next to itself.
pub const MOK_MANAGER: &str = r"\EFI\Microsoft\Boot\mmx64.efi";

/// Where the shim looks for the loader it runs: this image, under the name it
/// was staged with. The file can go while the image runs, because the
/// firmware loaded it into memory already.
pub const RENAMED_LOADER: &str = r"\EFI\Microsoft\Boot\grubx64.efi";

/// Puts the original boot manager back, with the metadata it had before the
/// host tool replaced it.
///
/// # Errors
///
/// Fails if the backup cannot be read, or the shim cannot be replaced by it.
pub fn restore(volume: &mut Volume) -> Result<()> {
    let (bytes, saved) = volume.read_saved(BACKUP)?;

    volume.delete(PATH)?;
    volume.write_saved(PATH, &bytes, &saved)?;

    println!("insecure-boot: the Windows boot manager is back in place");

    Ok(())
}

/// Loads the restored boot manager from its own path and starts it.
///
/// Starting it does not return on a machine that boots: coming back means
/// Windows did not, and that is reported as the error it is.
///
/// # Errors
///
/// Fails if the image cannot be loaded from its path, or it returns instead
/// of booting Windows.
pub fn start() -> Result<()> {
    let device_path = fs::file_device_path(PATH)?;

    let image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: &device_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )?;

    boot::start_image(image)?;

    Err(Error::BootManagerReturned)
}
