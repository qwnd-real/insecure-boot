/* Aggregates the uACPI public headers that the Rust bindings are generated
 * from. Kept separate from the upstream tree so the submodule stays pristine. */

#include <uacpi/acpi.h>
#include <uacpi/context.h>
#include <uacpi/event.h>
#include <uacpi/io.h>
#include <uacpi/kernel_api.h>
#include <uacpi/log.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/opregion.h>
#include <uacpi/osi.h>
#include <uacpi/registers.h>
#include <uacpi/resources.h>
#include <uacpi/sleep.h>
#include <uacpi/status.h>
#include <uacpi/tables.h>
#include <uacpi/types.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

/* uacpi_cpu_flags and uacpi_interrupt_state are spelled `unsigned long`, which
 * is 32 bits wide in this ABI while Rust's core::ffi::c_ulong is 64 bits wide
 * on x86_64-unknown-uefi. The bindings therefore substitute fixed-width
 * aliases; fail the build loudly rather than emit a silent mismatch if the
 * width this assumes ever changes. */
_Static_assert(sizeof(unsigned long) == 4, "unexpected width for unsigned long");

