# CLAUDE.md

Guidance for working in the `insecure-boot` repository.

## Project

A UEFI application in Rust that brings ACPI up through
[uACPI](https://github.com/uACPI/uACPI) and drives a TPM 2.0 Command Response
Buffer interface. It is the seed of a loader; everything runs before
`ExitBootServices`, which is what lets the layers below assume a flat
identity-mapped address space, a live console, and boot-service delays.

```
Cargo.toml               workspace root: members, shared deps, lint policy
rust-toolchain.toml      pinned channel, components, and UEFI target
rustfmt.toml             pinned formatting style edition
.cargo/config.toml       default build target (x86_64-unknown-uefi)
third-party/uacpi/       uACPI submodule, pinned to a release tag
crates/uacpi-sys/        uACPI compiled for the UEFI ABI, plus raw bindings
crates/ib-uacpi/         the uacpi_kernel_* host primitives and safe wrappers
crates/ib-tpm-crb/       TPM 2.0 driver for the CRB interface
crates/ib-loader/        the UEFI application; produces ib-loader.efi
```

Crates are prefixed `ib-`, except `-sys` crates, which keep the upstream
library's name. The build target is `x86_64-unknown-uefi` by default, so plain
`cargo build` produces `target/x86_64-unknown-uefi/debug/ib-loader.efi`.

Building needs `clang` and `llvm-ar` for the uACPI sources, because `cc` has no
built-in toolchain mapping for the UEFI targets and a host compiler emits objects
the UEFI linker cannot read, plus `libclang` for `bindgen`.

## Commands

```sh
git submodule update --init  # required once; uacpi-sys will not build without it
cargo build                  # zero warnings required
cargo clippy --all-targets   # zero warnings required
cargo fmt --all -- --check   # no diff required
```

Booting the image in QEMU with OVMF, which mirrors the firmware console to
serial, and with a software TPM behind a CRB interface:

```sh
mkdir -p esp/EFI/BOOT tpmstate
cp target/x86_64-unknown-uefi/debug/ib-loader.efi esp/EFI/BOOT/BOOTX64.EFI
cp /usr/share/edk2/x64/OVMF_VARS.4m.fd vars.fd
swtpm socket --tpm2 --tpmstate dir=tpmstate --ctrl type=unixio,path=swtpm.sock \
  --flags not-need-init,startup-clear --daemon
qemu-system-x86_64 -machine q35 -m 512 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive format=raw,file=fat:rw:esp \
  -chardev socket,id=chrtpm,path=swtpm.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-crb,tpmdev=tpm0 \
  -display none -serial stdio -net none
```

Dropping the last three device options boots a machine with no TPM, which is the
other path worth checking.

## 4. Coding style — hard rules

These are hard rules, not preferences:

- **No section-banner comments.** Never write `// ----- Console -----` or
  `// ===== Boot services =====`. Structure the code (modules, functions, types,
  ordering) so it stays readable without banners. Order items top-down: public
  entry points first, helpers after, so a reader never needs a banner to
  navigate.
- **Every `unsafe` block requires a `// SAFETY:` comment immediately above
  it**, explaining why the operation is sound *at that call site* — the
  invariants that hold and who guarantees them — not a restatement of what the
  code does. Every `unsafe fn` documents its contract in a `# Safety` doc
  section. This is mechanically enforced (§5).
- **Every module gets a `//!` doc comment** describing its purpose and, where
  relevant, the invariants it upholds. **Every public item gets a `///` doc
  comment.** Comment anything a competent reader would otherwise find unclear
  — and nothing that is already obvious from the code.
- **Comments are self-contained.** Never cite process artifacts anywhere in
  the repository — not in code comments, manifest/config comments, docs, or
  commit messages. Prohibited: references to this file or its sections, user
  review feedback, PR threads, or conversation history ("per review",
  "as discussed", "see Review paragraph 5", "allowed by §4"). State the actual
  technical reason in place instead: process references are meaningless to a
  future reader and rot as those documents change.
- **No unclean code.** No dead code, no commented-out code, no debug leftovers,
  no orphaned imports. If *your* change makes something unused, remove it; do
  not remove pre-existing dead code unless asked (report it instead).
- **Idiomatic Rust throughout.** Prefer `Result`/`Option` combinators over
  manual matching where they read better. Use newtypes over bare integers for
  anything with semantic meaning (physical/virtual addresses, register field
  offsets, vector numbers). No magic numbers and no stringly-typed code — use
  named constants, `enum`s, and `bitflags`-style types.
- **`unsafe` stays confined.** Raw hardware access (MSRs, control registers,
  port I/O, raw pointers into physical memory, privileged instructions)
  belongs in dedicated low-level modules/crates and is exposed to the rest of
  the codebase through safe wrappers wherever a sound safe wrapper is
  possible. Higher-level code should very rarely contain `unsafe` directly.
- **No panics in steady-state runtime code.** Anything on an eventual
  post-handoff runtime path must not panic during normal operation — use
  `Result` and propagate. Panics (`expect`, asserts) are acceptable only during
  early boot/init inside `ib-loader`, before control is handed off, where
  aborting the boot is the correct response to a broken invariant.
- **Performance is a requirement, not an afterthought** — but never at the
  cost of correctness or clarity without measurement. Avoid allocation and
  copying on hot paths; if you trade clarity for speed, justify it in a
  comment.

## 5. Lint policy — zero warnings, no exceptions by default

Enforced at the workspace level in the root `Cargo.toml`:

- `clippy::pedantic` is **deny**. All rustc warnings are **deny**. There is no
  "warnings allowed" mode: a build or clippy run that emits any warning or
  error is a failed build, full stop.
- `clippy::undocumented_unsafe_blocks` and `clippy::missing_safety_doc` are
  **deny** — they mechanically enforce the `SAFETY:` rule.
- `missing_docs` (rustc) is **deny** — it mechanically enforces public-item
  and crate docs.
- `clippy::allow_attributes_without_reason` is **deny** — every exception must
  carry a written reason.

When a pedantic lint is *actively wrong* for legitimate low-level work (e.g.
numeric-cast lints firing on intentional pointer/field-width truncation) and no
compliant rewrite exists:

1. Prefer `#[expect(lint_name, reason = "one-line why")]` on the **narrowest
   possible item** — never at module or crate level, never a blanket group
   downgrade.
2. Tell the user which lint you excepted and why, in your summary.

Suppressing a lint to hide a real problem, to save time, or because a fix is
inconvenient is prohibited.

## 6. Dependency policy

- Prefer established ecosystem crates over hand-rolled code: `uefi`
  (rust-osdev) for all UEFI protocol/boot-services work, and for future
  low-level work crates like `x86_64`, `raw-cpuid`, `bitflags`, `spin` — check
  what already exists before writing register/instruction wrappers by hand.
- Before adding a dependency: confirm nothing in the workspace or the existing
  dependency tree already covers the need, confirm it works in `no_std` for
  firmware-side crates, and state in your summary why it was added.
- Add dependencies to `[workspace.dependencies]` with an explicit version;
  enable only the features actually needed.
- Do not vendor, fork, or copy-paste code out of crates.

## 7. How to work (behavioral rules)

**Think before coding.**
- State your assumptions explicitly before implementing. Uncertain → ask.
- Multiple interpretations → present them; do not pick one silently.
- If a simpler approach than the requested one exists, say so — push back
  when warranted, before writing code.

**Simplicity first.**
- Minimum code that solves the stated problem. No speculative features,
  no abstractions for single-use code, no unrequested configurability,
  no error handling for impossible states.

**Surgical changes.**
- Match the existing style even where you would personally differ.
- Do not reformat or restructure untouched code.
- Clean up only the orphans your own change created.

**Goal-driven execution.**
- Turn every task into a verifiable goal before starting ("builds a working
  `.efi`", "clippy clean", "boots in QEMU and prints X") and state a brief
  step → verify plan for multi-step work.
- Loop until the verification actually passes; never claim success you have
  not observed. If a gate fails and you cannot fix it within the rules above,
  report the failure honestly with the output.

## 8. Commit conventions

- **Subject format:** `<area>: <imperative summary>` — e.g.
  `loader: print firmware revision at boot`. Lowercase, imperative mood
  ("add", not "added" or "adds"), no trailing period, whole subject line
  ≤ 72 characters.
- **Areas:** `loader` (ib-loader), `uacpi` (ib-uacpi), `uacpi-sys`, `tpm-crb`
  (ib-tpm-crb), `workspace` (root manifests, toolchain, lint/format/config
  files, third-party submodules), `docs` (documentation-only changes). A new
  crate introduces its own area named after the crate minus the `ib-` prefix.
- **Body:** separated from the subject by one blank line, prose wrapped at
  72 columns. Explain *what* changed and *why* — motivation and non-obvious
  consequences — not a replay of the diff. Trivial self-explanatory changes
  may omit the body.
- **Self-contained** (§4): commit messages never cite this file, reviews, or
  conversation history; they carry the actual reasoning themselves.
- **One logical change per commit.** Never mix a refactor with a behavior
  change, or formatting churn with anything else.
- **Every commit passes the Definition of done (§9).** Never commit code that
  fails a gate or is "fixed in the next commit". `Cargo.lock` changes are
  committed together with the manifest change that caused them.
- **Commit only when the user asks.** Never push, tag, amend, or rewrite
  history unprompted.

## 9. Definition of done

A change may be presented as finished only when ALL of the following hold:

1. `cargo build` succeeds with **zero** warnings.
2. `cargo clippy --all-targets` succeeds with **zero** warnings.
3. `cargo fmt --all -- --check` reports no diff.
4. No `unsafe` block lacks a `SAFETY:` comment; no public item or module lacks
   docs (the lints in §5 verify this mechanically — do not rely on memory).
5. No TODOs, stubs, dead code, or commented-out code were introduced.
6. Any lint exception added is `#[expect(..., reason = "...")]`, maximally
   narrow, and disclosed in your summary.
7. The diff contains nothing unrelated to the request.

If any item fails, the task is not done — say so explicitly.




