//! The boot volume: the file system this image was loaded from.
//!
//! Everything the loader consumes — the replay dump, the payload, the boot
//! manager backup — is staged into that one volume by the host tool before the
//! boot, so the loader does not search for files across every file system the
//! firmware knows: the image's own `LoadedImage` names the device it came from,
//! and that device's file system is the one to open.

use alloc::vec;
use alloc::vec::Vec;
use core::mem::MaybeUninit;

use uefi::boot;
use uefi::proto::device_path::{DevicePath, PoolDevicePath, build};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::runtime::Time;
use uefi::{CStr16, Status};

use crate::error::{Error, Result};

/// Length of a buffer holding the longest volume path as UCS-2, including the
/// terminator the firmware expects.
const NAME_CAPACITY: usize = 64;

/// Length of a buffer holding the largest file-path device-path node: the
/// four header bytes plus the longest path as UCS-2 with its terminator.
const NODE_CAPACITY: usize = 4 + NAME_CAPACITY * size_of::<u16>();

/// Length of the run of zeros a file is wiped with at a time.
const WIPE_CHUNK: usize = 4 * 1024;

/// Length of the fixed part of a `FileInfo`: everything before the name.
const INFO_HEADER: usize = 80;

/// The alignment a `FileInfo` storage buffer is brought up to, and so the
/// slack a misaligned buffer may lose to that.
const INFO_ALIGNMENT: usize = 8;

/// The root directory of the file system this image was loaded from.
pub struct Volume {
    root: Directory,
}

/// The metadata of a file that [`Volume::write_saved`] puts back on a copy.
pub struct Saved {
    /// When the file was created.
    create: Time,
    /// When the file was last read.
    access: Time,
    /// When the file was last written.
    modified: Time,
    /// The file's attribute bits.
    attribute: FileAttribute,
}

/// Opens the root directory of the file system the loader itself was loaded
/// from.
///
/// # Errors
///
/// Fails if the firmware cannot name that file system or open its root.
pub fn open() -> Result<Volume> {
    let mut file_system = boot::get_image_file_system(boot::image_handle())?;
    let root = file_system.open_volume()?;
    Ok(Volume { root })
}

impl Volume {
    /// Reads `path` from the root of the boot volume, reporting a file that is
    /// not there as [`None`].
    ///
    /// # Errors
    ///
    /// Fails if `path` cannot be spelled for the firmware's file protocol, or
    /// the volume refuses to serve a file that is there.
    pub fn read_optional(&mut self, path: &'static str) -> Result<Option<Vec<u8>>> {
        match self.open(path, FileMode::Read)? {
            Some(file) => contents(path, file).map(Some),
            None => Ok(None),
        }
    }

    /// Reads `path` from the root of the boot volume, treating its absence as
    /// an error.
    ///
    /// # Errors
    ///
    /// Fails as [`Volume::read_optional`] does, or if the file is not there.
    pub fn read(&mut self, path: &'static str) -> Result<Vec<u8>> {
        self.read_optional(path)?
            .ok_or(Error::MissingArtifact(path))
    }

    /// Reads `path` from the root of the boot volume together with the
    /// metadata a copy of it should keep.
    ///
    /// # Errors
    ///
    /// Fails as [`Volume::read_optional`] does, or if the file is not there.
    pub fn read_saved(&mut self, path: &'static str) -> Result<(Vec<u8>, Saved)> {
        let Some(mut file) = self.open(path, FileMode::Read)? else {
            return Err(Error::MissingArtifact(path));
        };

        let info = file.get_boxed_info::<FileInfo>()?;
        let saved = Saved {
            create: *info.create_time(),
            access: *info.last_access_time(),
            modified: *info.modification_time(),
            attribute: info.attribute(),
        };

        Ok((contents(path, file)?, saved))
    }

    /// Writes `bytes` to `path` in the root of the boot volume, giving the
    /// file the metadata `saved` records: the times and attributes it had
    /// before it was read.
    ///
    /// # Errors
    ///
    /// Fails if `path` cannot be spelled for the firmware's file protocol, or
    /// the volume refuses to take the bytes or the metadata.
    pub fn write_saved(&mut self, path: &'static str, bytes: &[u8], saved: &Saved) -> Result<()> {
        let mut file = self.create(path)?;

        file.write(bytes).map_err(|error| Error::PartialWrite {
            path,
            written: *error.data(),
            expected: bytes.len(),
        })?;

        let info = file.get_boxed_info::<FileInfo>()?;
        let name = info.file_name();
        let name_size = name.as_slice_with_nul().len() * size_of::<u16>();

        let mut storage = vec![0_u8; INFO_HEADER + name_size + INFO_ALIGNMENT];
        let info = FileInfo::new(
            &mut storage,
            bytes.len() as u64,
            bytes.len() as u64,
            saved.create,
            saved.access,
            saved.modified,
            saved.attribute,
            name,
        )
        .map_err(|_| Error::Metadata(path))?;

        file.set_info(info)?;

        Ok(())
    }

    /// Overwrites every byte of `path` in the root of the boot volume with
    /// zeros, flushes it, and deletes it.
    ///
    /// # Errors
    ///
    /// Fails if the file is not there, or the volume refuses to overwrite,
    /// flush, or delete it.
    pub fn wipe(&mut self, path: &'static str) -> Result<()> {
        let mut file = self
            .open(path, FileMode::ReadWrite)?
            .ok_or(Error::MissingArtifact(path))?;

        let expected = usize::try_from(file.get_boxed_info::<FileInfo>()?.file_size())
            .map_err(|_| Error::Oversized(path))?;

        let zeros = [0_u8; WIPE_CHUNK];
        let mut remaining = expected;
        while remaining > 0 {
            let len = remaining.min(WIPE_CHUNK);

            file.write(&zeros[..len])
                .map_err(|error| Error::PartialWrite {
                    path,
                    written: *error.data(),
                    expected: len,
                })?;

            remaining -= len;
        }

        file.flush()?;
        file.delete().map_err(Error::from)
    }

    /// Deletes `path` from the root of the boot volume.
    ///
    /// # Errors
    ///
    /// Fails if the file is not there, or the volume refuses to delete it.
    pub fn delete(&mut self, path: &'static str) -> Result<()> {
        self.open(path, FileMode::ReadWrite)?
            .ok_or(Error::MissingArtifact(path))?
            .delete()
            .map_err(Error::from)
    }

    /// Creates `path` in the root of the boot volume as a regular file, or
    /// opens it at its start if it is already there.
    fn create(&mut self, path: &'static str) -> Result<RegularFile> {
        let mut buffer = [0_u16; NAME_CAPACITY];
        let name = CStr16::from_str_with_buf(path, &mut buffer).map_err(|_| Error::Name(path))?;

        let file = self
            .root
            .open(name, FileMode::CreateReadWrite, FileAttribute::empty())?;

        file.into_regular_file().ok_or(Error::NotAFile(path))
    }

    /// Opens `path` in the root of the boot volume as a regular file, treating
    /// its absence as [`None`].
    fn open(&mut self, path: &'static str, mode: FileMode) -> Result<Option<RegularFile>> {
        let mut buffer = [0_u16; NAME_CAPACITY];
        let name = CStr16::from_str_with_buf(path, &mut buffer).map_err(|_| Error::Name(path))?;

        let file = match self.root.open(name, mode, FileAttribute::empty()) {
            Ok(file) => file,
            Err(error) if error.status() == Status::NOT_FOUND => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        Ok(Some(file.into_regular_file().ok_or(Error::NotAFile(path))?))
    }
}

/// Builds the full device path naming `path` in the root of the boot volume,
/// the way the firmware would have named it had the image been loaded from
/// there.
///
/// # Errors
///
/// Fails if the volume's own device path cannot be found, or the file's
/// cannot be assembled onto it.
pub fn file_device_path(path: &'static str) -> Result<PoolDevicePath> {
    let loaded = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let device = loaded.device().ok_or(Error::DevicePath)?;
    let volume = boot::open_protocol_exclusive::<DevicePath>(device)?;

    let mut names = [0_u16; NAME_CAPACITY];
    let name = CStr16::from_str_with_buf(path, &mut names).map_err(|_| Error::Name(path))?;

    let mut nodes = [MaybeUninit::uninit(); NODE_CAPACITY];
    let file: &DevicePath = build::DevicePathBuilder::with_buf(&mut nodes)
        .push(&build::media::FilePath { path_name: name })
        .map_err(|_| Error::DevicePath)?
        .finalize()
        .map_err(|_| Error::DevicePath)?;

    volume.append_path(file).map_err(|_| Error::DevicePath)
}

/// Reads a whole open file into memory.
///
/// # Errors
///
/// Fails if the file's size cannot be addressed, or the volume serves fewer
/// bytes than that size.
fn contents(path: &'static str, mut file: RegularFile) -> Result<Vec<u8>> {
    let info = file.get_boxed_info::<FileInfo>()?;
    let expected = usize::try_from(info.file_size()).map_err(|_| Error::Oversized(path))?;

    let mut bytes = vec![0_u8; expected];
    let read = file.read(&mut bytes)?;

    if read != expected {
        return Err(Error::PartialRead {
            path,
            read,
            expected,
        });
    }

    Ok(bytes)
}
