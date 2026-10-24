# RustCloak

An LLVM-IR code-protection pass for Rust (and any LLVM frontend) — the "red team" counterpart to
the [rust-deobf](https://github.com/VAHPEM/rust-deobf) analysis toolkit. RustCloak hardens a binary
against reverse engineering at the LLVM intermediate-representation level, where the transforms are
language-agnostic and survive codegen. It is built as a standard **new pass-manager plugin** against
stock LLVM (no LLVM fork), so it builds in minutes, not hours.

> Intended use: protecting proprietary software (anti-tamper, IP protection) and generating realistic
> obfuscated test cases for the rust-deobf analysis engine. It is a software-protection tool, not
> malware.

## Status — v0

**Control-flow flattening (`flatten`)** — implemented and working. Each function is rewritten into
the canonical flattened form (a switch-variable, a dispatcher, and blocks that transition by
assigning the next state), hiding the original block order in a runtime state machine. This is the
classic flattening algorithm (Wang et al.); the implementation in `src/Flatten.cpp` is original, not
copied from Obfuscator-LLVM. It demotes PHIs and cross-block values to stack first so rewiring the
control flow cannot violate SSA dominance, and it leaves functions with exception handling /
`indirectbr` / `switch` terminators untouched.

Verified: the flattened `test/demo.c` produces byte-identical output to the original, the IR passes
`opt -passes=verify`, and `decode()` grows from 6 to 9 blocks with the dispatcher state machine.

## Build

Needs LLVM 18 development headers (`llvm-18-dev`), CMake and a C++17 compiler.

```sh
cmake -S . -B build -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir)
cmake --build build          # -> build/libRustCloak.so
```

## Use

```sh
# C (or any clang frontend) at the IR level:
clang-18 -O1 -emit-llvm -S input.c -o input.ll
opt-18 -load-pass-plugin=build/libRustCloak.so -passes=flatten input.ll -S -o out.ll
clang-18 out.ll -o hardened

# round-trip check + behaviour check:
./test/build_and_test.sh
```

## Roadmap

- **Late pass ordering.** Run flattening at the *end* of the optimization pipeline. Applied before
  `-O2`, LLVM's own passes (mem2reg/SROA, jump-threading) partially undo it — at `-O2` the state
  variable is promoted to a register and the dispatcher becomes a `cmp reg,imm;je` chain. A
  production build registers the pass at `OptimizationPipelineEndEP` so the optimizer runs first.
- **More transforms:** string-literal encryption (encrypt globals, insert a decode stub — the
  transform rust-deobf's string engine targets), bogus control flow, instruction substitution, and
  an opaque-predicate pass.
- **Rust integration.** The pass is language-agnostic, but wiring it into `rustc` needs the plugin
  built against the *same* LLVM `rustc` ships (rustc 1.97 uses LLVM 22, the stock toolchain here is
  LLVM 18). Options: pin a rustc whose LLVM matches, build the pass against rustc's bundled LLVM, or
  load it via nightly `-Zllvm-plugins`. Until then the demo path is clang → IR → `opt` → binary.

## Relationship to rust-deobf (red/blue)

RustCloak's output is a realistic, *non-synthetic* target for rust-deobf's deflattener. It already
surfaced a real gap: rust-deobf detects only goldberg's specific `sub/je + scratch-copy` dispatcher,
while RustCloak's switch-lowered dispatcher (and real OLLVM's) is not yet recognized — a concrete,
general improvement for the analysis side.
