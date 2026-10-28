# Packing — design and why it is a separate subsystem (not shipped as an IR pass)

RustCloak hardens at the LLVM-IR level: every transform runs inside the compiler, is portable across
targets, and tracks only the stable IRBuilder API, so a new Rust/LLVM release every ~6 weeks costs
little to follow. **Executable packing does not fit that model**, and this note records the design
plus the deliberate decision to keep it out of the IR plugin for now.

## What packing is
Compress (and/or encrypt) the linked binary's code and data, replace the entry point with a small
**stub loader** that at run time decompresses the payload into freshly `mmap`-ed memory, applies
relocations, sets page protections (`mprotect` to make code executable), rebuilds whatever the
dynamic loader needs, and jumps to the original entry. This is what UPX / Themida's packer stage do.

## Why it is post-link and OS/format-specific
- It operates on the **final linked image**, after RustCloak's IR passes and the linker have run, so
  it cannot be an LLVM pass at all -- it is a separate tool over the `ELF`/`PE`/`Mach-O` file.
- The stub must speak the platform loader's contract: program headers and `PT_LOAD` layout, the
  dynamic section, `R_*_RELATIVE`/`IRELATIVE` relocations, TLS, `init_array`, GOT/PLT, stack
  setup -- all different per format and per OS, and all able to change with a libc or loader update.
- It interacts with the other features here: a packed image's `.text` is compressed at rest, so the
  anti-tamper section hash must be computed over the *unpacked* bytes (hash after the stub inflates,
  or hash the compressed blob); the strenc/license constructors must run *after* unpacking.

## Maintenance cost (the reason it is deferred)
A packer is the highest-maintenance component imaginable for the stated constraint: it is coupled to
loader internals that are outside our control and that move independently of the ~6-week LLVM/Rust
cadence. A single glibc/loader change can silently break the stub on one distro while another works
-- exactly the "measure before you conclude, per-arch" discipline this project follows, but with a
much larger and OS-dependent test matrix (every ELF/PE/Mach-O x every libc/loader version).

## Recommendation
1. For shipping protected binaries now, run an existing, maintained packer (e.g. UPX for ELF/PE) as a
   final step *after* RustCloak, keeping anti-tamper/strenc/license constructors unpack-aware.
2. If a bespoke packer is built, scope it as its own repo/tool with a per-platform stub and its own
   loader test matrix, versioned against each target OS -- never inside the IR plugin, whose value is
   precisely that it is loader-agnostic and cheap to maintain.

The IR-level pieces of "section C" that DO fit the model are shipped: import/API hiding
(`RUSTCLOAK_HIDE_IMPORTS`, dlsym-by-encrypted-name) and the license key gate (`RUSTCLOAK_LICENSE`).
