//! Device lookup and method evaluation in the ACPI namespace.

use core::ffi::{CStr, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

use uacpi_sys::{
    UACPI_ITERATION_DECISION_BREAK, UACPI_ITERATION_DECISION_CONTINUE, uacpi_eval, uacpi_eval_hid,
    uacpi_free_id_string, uacpi_id_string, uacpi_iteration_decision, uacpi_namespace_node,
    uacpi_object, uacpi_object_array, uacpi_object_create_buffer, uacpi_object_create_integer,
    uacpi_object_create_package, uacpi_object_get_integer, uacpi_object_unref, uacpi_u32,
    uacpi_u64,
};

use crate::error::{Error, Result, check};
use crate::resources::Resources;

/// Length of a binary ACPI GUID, as passed to `_DSM`.
pub const GUID_LEN: usize = 16;

/// A device node in the ACPI namespace.
#[derive(Clone, Copy)]
pub struct Device(NonNull<uacpi_namespace_node>);

/// The `_HID` string of a device, owned by uACPI until dropped.
pub struct HardwareId(NonNull<uacpi_id_string>);

/// Finds the first device whose `_HID` or `_CID` matches `id`, for example
/// `c"MSFT0101"`.
///
/// # Errors
///
/// Fails if the namespace walk itself fails; a namespace with no matching device
/// is reported as [`None`].
pub fn find_device(id: &CStr) -> Result<Option<Device>> {
    let mut found: Option<Device> = None;

    // SAFETY: `id` is NUL-terminated for the duration of the call, `collect` has
    // the signature uACPI expects, and the context pointer refers to `found`,
    // which outlives the walk.
    let status = unsafe {
        uacpi_sys::uacpi_find_devices(
            id.as_ptr(),
            Some(collect),
            ptr::from_mut(&mut found).cast::<c_void>(),
        )
    };
    check(status)?;

    Ok(found)
}

impl Device {
    /// Evaluates `_DSM` for `guid`, `revision` and `index`, and returns the
    /// integer it produced.
    ///
    /// The four arguments are the ones the ACPI specification defines for `_DSM`:
    /// the interface GUID as a buffer, the interface revision, the function
    /// index, and a package of function-specific arguments, which is empty here
    /// because no `_DSM` this workspace calls takes any.
    ///
    /// # Errors
    ///
    /// Fails if the device has no `_DSM`, if AML execution fails, if uACPI cannot
    /// allocate the arguments, or if the method returns something other than an
    /// integer.
    pub fn eval_dsm_integer(
        &self,
        guid: &[u8; GUID_LEN],
        revision: uacpi_u64,
        index: uacpi_u64,
    ) -> Result<uacpi_u64> {
        let owned = [
            Object::buffer(guid)?,
            Object::integer(revision)?,
            Object::integer(index)?,
            Object::empty_package()?,
        ];
        let mut borrowed = owned.each_ref().map(|object| object.0);
        let arguments = uacpi_object_array {
            objects: borrowed.as_mut_ptr(),
            count: borrowed.len(),
        };

        let mut returned: *mut uacpi_object = ptr::null_mut();

        // SAFETY: the node is live, `c"_DSM"` is NUL-terminated, every object
        // `arguments` points at is kept alive by `owned` for the duration of the
        // call, and `returned` is a writable slot for the result.
        let status = unsafe {
            uacpi_eval(
                self.0.as_ptr(),
                c"_DSM".as_ptr(),
                &raw const arguments,
                &raw mut returned,
            )
        };
        check(status)?;

        let returned = Object(returned);

        let mut value: uacpi_u64 = 0;

        // SAFETY: `returned` holds the object uACPI produced and `value` is a
        // writable destination.
        check(unsafe { uacpi_object_get_integer(returned.0, &raw mut value) })?;

        Ok(value)
    }

    /// The device's `_HID`.
    ///
    /// # Errors
    ///
    /// Fails if the device has no `_HID` or if evaluating it fails.
    pub fn hardware_id(&self) -> Result<HardwareId> {
        let mut id: *mut uacpi_id_string = ptr::null_mut();

        // SAFETY: the node is live and `id` is a writable slot for the result.
        check(unsafe { uacpi_eval_hid(self.0.as_ptr(), &raw mut id) })?;

        NonNull::new(id)
            .map(HardwareId)
            .ok_or_else(Error::malformed)
    }

    /// The device's current resource settings, from `_CRS`.
    ///
    /// # Errors
    ///
    /// Fails if the device has no `_CRS` or if evaluating or decoding it fails.
    pub fn resources(&self) -> Result<Resources> {
        Resources::current_for(self.0)
    }
}

impl HardwareId {
    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // SAFETY: uACPI hands out a NUL-terminated string whose storage it keeps
        // alive until `uacpi_free_id_string`, which only runs when `self` drops.
        let text = unsafe { CStr::from_ptr(self.0.as_ref().value) };
        text.to_str().unwrap_or_default()
    }
}

impl fmt::Display for HardwareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Drop for HardwareId {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `uacpi_eval_hid` and has not been freed.
        unsafe { uacpi_free_id_string(self.0.as_ptr()) };
    }
}

/// A uACPI object this crate owns a reference to.
struct Object(*mut uacpi_object);

impl Object {
    /// Wraps a freshly created object, failing if uACPI could not allocate it.
    fn new(object: *mut uacpi_object) -> Result<Self> {
        if object.is_null() {
            Err(Error::out_of_memory())
        } else {
            Ok(Self(object))
        }
    }

    /// A buffer object holding a copy of `bytes`.
    fn buffer(bytes: &[u8]) -> Result<Self> {
        let view = uacpi_sys::uacpi_data_view {
            __bindgen_anon_1: uacpi_sys::uacpi_data_view__bindgen_ty_1 {
                const_bytes: bytes.as_ptr(),
            },
            length: bytes.len(),
        };

        // SAFETY: `view` describes `bytes`, which outlives the call, and uACPI
        // copies the contents into the object it returns.
        Self::new(unsafe { uacpi_object_create_buffer(view) })
    }

    /// An integer object holding `value`.
    fn integer(value: uacpi_u64) -> Result<Self> {
        // SAFETY: creating an integer object reads no memory through pointers.
        Self::new(unsafe { uacpi_object_create_integer(value) })
    }

    /// A package object with no elements.
    fn empty_package() -> Result<Self> {
        let array = uacpi_object_array {
            objects: ptr::null_mut(),
            count: 0,
        };

        // SAFETY: an array of zero elements is never dereferenced, so the null
        // pointer is not read.
        Self::new(unsafe { uacpi_object_create_package(array) })
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null object this type holds a reference to,
        // and dropping releases exactly that reference.
        unsafe { uacpi_object_unref(self.0) };
    }
}

/// Records the first matching device and stops the namespace walk.
///
/// # Safety
///
/// `user` must point to an `Option<Device>` that outlives the walk, and `node`
/// must be the live namespace node uACPI is visiting.
unsafe extern "C" fn collect(
    user: *mut c_void,
    node: *mut uacpi_namespace_node,
    _node_depth: uacpi_u32,
) -> uacpi_iteration_decision {
    let Some(node) = NonNull::new(node) else {
        return UACPI_ITERATION_DECISION_CONTINUE;
    };

    // SAFETY: `find_device` passes a pointer to its own `found` local, which
    // outlives the walk, and the walk is single-threaded so no other reference
    // to it exists.
    unsafe { *user.cast::<Option<Device>>() = Some(Device(node)) };

    UACPI_ITERATION_DECISION_BREAK
}
