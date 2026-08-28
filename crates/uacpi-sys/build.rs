//! Compiles the vendored uACPI translation units for the UEFI ABI and generates
//! the raw Rust bindings from its public headers.

use std::env;
use std::path::{Path, PathBuf};

/// Translation units that make up uACPI, mirroring upstream `source/files.cmake`.
const SOURCES: &[&str] = &[
    "default_handlers.c",
    "event.c",
    "interpreter.c",
    "io.c",
    "mutex.c",
    "namespace.c",
    "notify.c",
    "opcodes.c",
    "opregion.c",
    "osi.c",
    "registers.c",
    "resources.c",
    "shareable.c",
    "sleep.c",
    "stdlib.c",
    "tables.c",
    "types.c",
    "uacpi.c",
    "utilities.c",
];

/// Preprocessor definition applied to both the C build and the bindings.
///
/// Reduced-hardware mode compiles out the event subsystem, the SCI interrupt
/// handler and the ACPI global lock. A UEFI application shares the machine with
/// firmware that still owns all three, so it must never claim them.
const REDUCED_HARDWARE: &str = "UACPI_REDUCED_HARDWARE";

/// Flags that make a freestanding UEFI-ABI translation unit out of a C source.
///
/// The UEFI x86-64 environment has no red zone available (firmware interrupt
/// handlers run on the active stack) and provides no runtime support for stack
/// probes or stack-protector bookkeeping.
const FREESTANDING_FLAGS: &[&str] = &[
    "-ffreestanding",
    "-fshort-wchar",
    "-mno-red-zone",
    "-fno-stack-protector",
    "-fno-stack-check",
];

/// Clang target triple that matches Rust's `x86_64-unknown-uefi`: COFF objects
/// using the Microsoft x64 calling convention.
const CLANG_TARGET: &str = "x86_64-unknown-windows-gnu";

/// C compiler used for the uACPI sources.
///
/// Clang can target the UEFI ABI out of the box; a host `cc` cannot.
const COMPILER: &str = "clang";

/// Archiver used for the resulting objects, which are COFF rather than ELF.
const ARCHIVER: &str = "llvm-ar";

/// uACPI typedefs whose C spelling is `unsigned long` and whose generated alias
/// must therefore be replaced.
///
/// `core::ffi::c_ulong` is 64 bits wide on `x86_64-unknown-uefi` while the C ABI
/// makes `unsigned long` 32 bits wide. Both typedefs are opaque cookies that
/// travel from uACPI to the host and straight back, so a fixed-width alias
/// describes them exactly. `wrapper.h` asserts the width this relies on.
const ABI_MISMATCHED_TYPES: &[(&str, &str)] =
    &[("uacpi_cpu_flags", "u32"), ("uacpi_interrupt_state", "u32")];

fn main() {
    let uacpi = uacpi_dir();
    let include = uacpi.join("include");

    println!("cargo::rerun-if-changed=wrapper.h");
    println!("cargo::rerun-if-changed={}", include.display());

    compile(&uacpi, &include);
    generate_bindings(&include);
}

/// Locates the uACPI checkout, failing with an actionable message when the
/// submodule has not been populated.
fn uacpi_dir() -> PathBuf {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets this"));
    let uacpi = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate lives two levels below the workspace root")
        .join("third-party/uacpi");

    assert!(
        uacpi.join("source/uacpi.c").is_file(),
        "uACPI sources are missing from {}; run `git submodule update --init`",
        uacpi.display()
    );

    uacpi
}

/// Builds the uACPI sources into a static archive for the current target.
///
/// The toolchain has to be named explicitly: `cc` has no built-in mapping for the
/// UEFI targets, so left alone it would reach for the host compiler and emit ELF
/// objects that the UEFI linker, which is `lld` in `link.exe` mode, cannot read.
fn compile(uacpi: &Path, include: &Path) {
    let mut build = cc::Build::new();
    build
        .compiler(COMPILER)
        .archiver(ARCHIVER)
        .flag(format!("--target={CLANG_TARGET}"))
        .include(include)
        .define(REDUCED_HARDWARE, None)
        .files(SOURCES.iter().map(|src| uacpi.join("source").join(src)))
        // DWARF section names do not fit COFF's eight-character limit, which makes
        // the linker fall back to a non-standard string table and say so. Debug
        // info for vendored C is not worth a warning on every link.
        .debug(false)
        .warnings(false);

    for flag in FREESTANDING_FLAGS {
        build.flag(flag);
    }

    for src in SOURCES {
        println!(
            "cargo::rerun-if-changed={}",
            uacpi.join("source").join(src).display()
        );
    }

    build.compile("uacpi");
}

/// Generates the raw bindings into `OUT_DIR/bindings.rs`.
fn generate_bindings(include: &Path) {
    let mut clang_args = vec![
        format!("--target={CLANG_TARGET}"),
        format!("-I{}", include.display()),
        format!("-D{REDUCED_HARDWARE}"),
    ];
    clang_args.extend(FREESTANDING_FLAGS.iter().map(ToString::to_string));

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(&clang_args)
        .use_core()
        .ctypes_prefix("::core::ffi")
        .layout_tests(false)
        .prepend_enum_name(false)
        .allowlist_item("uacpi.*")
        .allowlist_item("UACPI.*")
        .allowlist_item("acpi_.*");

    let bindings = ABI_MISMATCHED_TYPES
        .iter()
        .fold(bindings, |bindings, (name, rust)| {
            bindings
                .blocklist_type(name)
                .raw_line(format!("pub type {name} = {rust};"))
        })
        .generate()
        .expect("uACPI headers are self-contained and parse standalone");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets this"));
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("OUT_DIR is writable");
}
