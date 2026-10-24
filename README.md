# RustCloak

An LLVM-IR code-protection pass for Rust (and any LLVM frontend) — the "red team" counterpart to
the [rust-deobf](https://github.com/VAHPEM/rust-deobf) analysis toolkit. RustCloak hardens a binary
against reverse engineering at the LLVM intermediate-representation level, where the transforms are
language-agnostic and survive codegen. It is built as a standard **new pass-manager plugin** against
stock LLVM (no LLVM fork), so it builds in minutes, not hours.

> Intended use: protecting proprietary software (anti-tamper, IP protection) and generating realistic
> obfuscated test cases for the rust-deobf analysis engine. It is a software-protection tool, not
> malware.

## Status — v1

Three transforms, all implemented and working, applied **late** in the pipeline so the optimizer
cannot undo them:

- **Control-flow flattening (`flatten`).** Each function is rewritten into the canonical flattened
  form — a switch-variable, a dispatcher, and blocks that transition by assigning the next state —
  hiding the original block order in a runtime state machine. Original algorithm (Wang et al.), not
  copied from Obfuscator-LLVM. PHIs and cross-block values are demoted to stack first so rewiring
  the control flow cannot violate SSA dominance; functions with exception handling / `indirectbr` /
  `switch` terminators are left untouched.
- **String-literal encryption (`strenc`).** Every private constant i8 string is XOR-encrypted (a
  per-string keystream) in the object and made writable; a single shared decrypt routine is
  registered as a global constructor, so the plaintext exists only in memory at run time. The binary
  holds only ciphertext — `strings`/FLOSS see nothing.
- **Late ordering.** Loading the plugin into a default `-O` pipeline (`clang -O2 -fpass-plugin=…`)
  runs both transforms at `OptimizerLast`, after the optimizer, so flattening is not simplified away.
  (`RUSTCLOAK_OFF=1` disables the automatic insertion.)

Verified on `test/demo.c`: byte-identical output before/after; IR passes `opt -passes=verify`;
`decode()` gains the dispatcher state machine; at `-O2` the flattening survives (dispatcher rungs
present) and the plaintext string is absent from the binary. The flattened output is also recovered
end-to-end by [rust-deobf](https://github.com/VAHPEM/rust-deobf)'s deflattener (the red/blue loop).

## Build

Needs LLVM 18 development headers (`llvm-18-dev`), CMake and a C++17 compiler.

```sh
cmake -S . -B build -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir)
cmake --build build          # -> build/libRustCloak.so
```

## Use

```sh
# Production path: load the plugin into -O2; it obfuscates at the end of the pipeline.
clang-18 -O2 -fpass-plugin=build/libRustCloak.so input.c -o hardened

# Or apply a single transform explicitly on IR:
clang-18 -O1 -emit-llvm -S input.c -o input.ll
opt-18 -load-pass-plugin=build/libRustCloak.so -passes='strenc,flatten' input.ll -S -o out.ll
clang-18 out.ll -o hardened

# full self-check (flatten + strenc + -O2 survival):
./test/build_and_test.sh
```

## Roadmap

- **More transforms:** bogus control flow, instruction substitution, opaque predicates, and
  per-build randomised keys/seeds.
- **Rust integration.** The passes are language-agnostic, but wiring them into `rustc` needs the
  plugin built against the *same* LLVM `rustc` ships (rustc 1.97 uses LLVM 22; the stock toolchain
  here is LLVM 18). Options: pin a rustc whose LLVM matches, build against rustc's bundled LLVM, or
  load via nightly `-Zllvm-plugins`. Until then the demo path is clang → `-fpass-plugin` → binary.
- **Hardening:** protect the decrypt constructor itself, string-slice length handling, and
  anti-tamper checks.

## Relationship to rust-deobf (red/blue)

RustCloak's output is a realistic, *non-synthetic* target for rust-deobf's deflattener. It already
surfaced a real gap: rust-deobf detects only goldberg's specific `sub/je + scratch-copy` dispatcher,
while RustCloak's switch-lowered dispatcher (and real OLLVM's) is not yet recognized — a concrete,
general improvement for the analysis side.
