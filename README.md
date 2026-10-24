# RustCloak

**An LLVM-level code-protection tool (a code obfuscator) for Rust — and any LLVM-based language.**
RustCloak is the red-team counterpart to the [rust-deobf](https://github.com/VAHPEM/rust-deobf)
analysis toolkit: where rust-deobf *recovers* hidden strings and control flow from a binary,
RustCloak *hides* them, to make a program harder to reverse-engineer.

> **What it is for.** Protecting proprietary software (anti-tamper, intellectual-property
> protection) and generating realistic obfuscated test cases for the rust-deobf analysis engine.
> It is a software-protection tool, not malware.

---

## What it is

A program you compile is normally easy to read with a disassembler: the strings sit in plain text,
and the control flow (the `if`s and loops) maps straight back to the source. RustCloak rewrites the
program — **without changing what it does** — so that is no longer true. It works at the level of
**LLVM Intermediate Representation (IR)** — the common form every `clang`/`rustc` program passes
through on the way to machine code — so one implementation protects C, C++, Rust and anything else
built on LLVM, and the protection survives into the final binary.

Technically it is an **LLVM new-pass-manager plugin**: a shared library (`libRustCloak.so`) you load
into the compiler. It is built against stock LLVM (no LLVM fork), so it compiles in minutes.

## What it does — the four transforms

Each transform lives in its own source file and can be used alone or together.

1. **Control-flow flattening — `flatten` (`src/Flatten.cpp`).** The single most important transform.
   A function's blocks normally run in an order you can read off the branches. Flattening dissolves
   that: every block is given a random number, the function becomes one big `loop { switch(state) }`
   dispatcher, and each block ends by setting the *next* state number instead of branching directly.
   The original order is now hidden inside a runtime state variable — a reverse engineer sees a flat
   list of blocks reached through a switch, not the real shape. (Algorithm: Wang et al.; original
   implementation.)

2. **String-literal encryption — `strenc` (`src/StrEnc.cpp`).** Every private constant string is
   XOR-encrypted in the file with a per-string keystream, and a small decrypt routine is registered
   as a *global constructor* that restores the strings in memory just before `main` runs. On disk the
   binary holds only ciphertext — `strings` and FLOSS find nothing; the plaintext exists only while
   the program runs. (Handles both C's `[N x i8]` strings and Rust's wrapped `<{ [N x i8] }>` form.)

3. **Instruction substitution — `subst` (`src/Subst.cpp`).** Replaces simple arithmetic/logic with
   longer equivalent expressions, so the obvious operation is no longer obvious — e.g. `a + b` → `a -
   (-b)`, `a ^ b` → `(a & ~b) | (~a & b)`, `a & b` → `~(~a | ~b)`.

4. **Bogus control flow + opaque predicates — `bogus` (`src/Bogus.cpp`).** Splits blocks and guards
   the real path with an **opaque predicate** — a condition that is always true but that the compiler
   cannot fold away, because it is computed from a non-constant global (`(x*(x+1)) & 1 == 0`, always
   true since the product of consecutive integers is even). Each guarded block gains a fake alternate
   path that never executes but clutters the control-flow graph a reader must reason through.

**Per-build randomness.** All state numbers and keys come from a build seed. By default the seed is
random per build, so two builds of the same program differ (no two copies look alike); pass
`--rustcloak-seed=N` for a reproducible build.

**Late ordering.** When loaded into a normal `-O2` pipeline, the transforms run at `OptimizerLast` —
*after* the optimizer — so the optimizer's own passes cannot simplify the obfuscation away.

## How it works — the mechanism

LLVM lets you register extra passes through a plugin. `src/Plugin.cpp` exports the standard
`llvmGetPassPluginInfo` entry point and registers the four passes two ways: explicitly by name
(`-passes=flatten` etc.) and automatically at the end of any default `-O` pipeline. A pass is just a
function that receives one `Function` (or `Module`) of LLVM IR and rewrites it in place; because the
IR is the same whether it came from `clang` or `rustc`, the obfuscation is language-agnostic and is
baked into the binary by the normal backend.

Flattening has one correctness subtlety worth knowing: rewiring the control flow breaks LLVM's SSA
form (a value defined in one block and used in another is no longer guaranteed to be *dominated* by
its definition once blocks are reached through a dispatcher). RustCloak handles this by first
demoting such values — and all PHI nodes — to stack slots, so the rewrite is always safe.

## Build

Needs LLVM 18 development headers (`llvm-18-dev`), CMake and a C++17 compiler.

```sh
cmake -S . -B build -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir)
cmake --build build          # -> build/libRustCloak.so
```

## Use

```sh
# C / C++ — load the plugin into -O2; it obfuscates at the end of the pipeline:
clang-18 -O2 -fpass-plugin=build/libRustCloak.so input.c -o hardened

# Rust — via rustc's -Zllvm-plugins (nightly whose LLVM matches the plugin's LLVM):
rustc +nightly-2024-06-15 -O -Zllvm-plugins=$PWD/build/libRustCloak.so prog.rs -o hardened

# A single transform on IR, explicitly:
opt-18 -load-pass-plugin=build/libRustCloak.so -passes='strenc,function(subst,bogus,flatten)' in.ll -S -o out.ll
```

Self-checks (behaviour preserved + obfuscation present):

```sh
./test/build_and_test.sh                       # C: flatten + strenc + -O2 survival
RUSTCLOAK_NIGHTLY=nightly-2024-06-15 ./test/rust_demo.sh   # Rust: -Zllvm-plugins end to end
```

Verified: on both the C and Rust demos the obfuscated binary produces identical output, the secret
string is absent from the file, and the control flow is flattened. The flattened output is also
recovered end-to-end by rust-deobf's deflattener — the red/blue loop.

## Rust integration notes

`-Zllvm-plugins` is a **nightly** flag, and the plugin must be built against the **same LLVM major
version `rustc` ships** (rustc 1.81 / nightly-2024-06 use LLVM 18, matching `llvm-18-dev`; current
stable rustc uses a newer LLVM, so build the plugin against that LLVM to target it). On stable, or to
obfuscate only part of a crate, use the explicit IR path (`rustc --emit=llvm-ir` → `opt` → relink).

## Roadmap

- More opaque-predicate families and junk-code generators; protect the decrypt constructor itself.
- A `cargo` wrapper so a build is just `cargo rustcloak build`.
- Anti-debug / anti-tamper checks; MBA (mixed boolean-arithmetic) substitution.

## Layout

```
src/RustCloak.h   shared: build seed + RNG, pass declarations
src/Flatten.cpp   control-flow flattening
src/StrEnc.cpp    string-literal encryption
src/Subst.cpp     instruction substitution
src/Bogus.cpp     bogus control flow + opaque predicates
src/Plugin.cpp    plugin registration + late ordering
test/             C and Rust demos + self-tests
```
