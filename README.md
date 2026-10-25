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

## What it does — the five transforms

Each transform lives in its own source file and can be used alone or together.

1. **Control-flow flattening — `flatten` (`src/Flatten.cpp`).** The single most important transform.
   A function's blocks normally run in an order you can read off the branches. Flattening dissolves
   that: every block is given a random number, the function becomes one big `loop { switch(state) }`
   dispatcher, and each block ends by setting the *next* state number instead of branching directly.
   The original order is now hidden inside a runtime state variable — a reverse engineer sees a flat
   list of blocks reached through a switch, not the real shape. (Algorithm: Wang et al.; original
   implementation.)

2. **String-literal encryption — `strenc` (`src/StrEnc.cpp`).** Every private constant string is
   XOR-encrypted in the file with a per-string keystream. On disk the binary holds only ciphertext —
   `strings` and FLOSS find nothing. Two modes: by default a small decrypt routine runs as a *global
   constructor* and restores every string just before `main`; with **`RUSTCLOAK_LAZY=1`** each string
   instead gets its own getter that decrypts it **on first use** (guarded by a flag) and returns its
   pointer, and every use is redirected to that getter — so the plaintext exists in memory only once
   a string is actually touched, and only for strings a run reaches, defeating a startup memory dump
   or a dump of an un-taken path. (Lazy mode falls back to the eager constructor for any string whose
   uses it cannot safely redirect; the flag check is not yet thread-synchronised.) Handles both C's
   `[N x i8]` strings and Rust's wrapped `<{ [N x i8] }>` form.

   With **`RUSTCLOAK_ANTIEMU=1`** the decryption keys are additionally bound to loader-established
   state, to defeat emulation-based recovery. A marker byte starts at 0; a constructor emitted at
   priority 0 — so it runs *before* the decrypt constructor — stores a per-build random `MAGIC` into
   it, and every key is emitted as `key ^ MAGIC ^ load(marker)` with the marker read **volatile** so
   the compiler cannot fold it away. On a real run the marker holds `MAGIC`, the two cancel, and the
   real key is used — output is byte-identical to a normal build. But a tool that emulates functions
   in isolation never runs the constructor: the marker stays 0, every key is off by `MAGIC`, and
   nothing decodes. (Combines with lazy or eager mode. Countered in turn by an analyzer that replays
   global constructors first — see the red/blue notes — which is the point: it raises the floor.)

3. **Instruction substitution — `subst` (`src/Subst.cpp`).** Replaces arithmetic/logic with
   **mixed boolean-arithmetic (MBA)** expressions, each proven equivalent for all inputs with z3 —
   `a + b` → `(a ^ b) + 2·(a & b)`, `a - b` → `(a ^ b) − 2·(~a & b)`, `a ^ b` → `(a | b) − (a & b)`,
   `a & b` → `(a | b) − (a ^ b)`, `a | b` → `(a & b) + (a ^ b)` — mixing arithmetic and bitwise ops so
   the operation is far less obvious and resists simple pattern reversal.

4. **Bogus control flow + opaque predicates — `bogus` (`src/Bogus.cpp`).** Splits blocks and guards
   the real path with an **opaque predicate** — a condition that is always true but that the compiler
   cannot fold away, because it is computed from a non-constant global. **Five always-true families**
   are mixed per block (the seed picks one), each proven always-true over all 32-bit inputs with z3,
   so a deobfuscator cannot pattern-match a single shape: `(x·(x+1)) & 1 == 0`, `(x² + x) & 1 == 0`,
   `(x² ^ x) & 1 == 0`, `(x | 1) & 1 == 1`, and `(x&1)·(x&1) == (x&1)`. Each guarded block gains a
   fake alternate path that never executes but clutters the control-flow graph.

5. **Code virtualization — `virt` (`src/Virt.cpp`).** The strongest transform. Instead of leaving a
   function as native code, `virt` compiles its computation into a custom **bytecode** for a made-up
   **register machine (machine virtuelle à registres)** and replaces the function body with a
   **bytecode interpreter**. A reverse engineer no longer sees x86/ARM arithmetic for that function —
   they see a dispatch loop over opcodes whose semantics they must first reconstruct, and then a
   bytecode program they must decode. This is the technique behind VMProtect / Themida / Tigress,
   done here at the LLVM-IR level so the interpreter LLVM compiles is portable to any target. The
   virtual instruction set is register-based (a fixed array of iW registers, a constant pool, a
   4-byte `[opcode, dst, a, b]` instruction); the bytecode and pool are emitted as **mutable** globals
   read through **volatile** loads, so the optimizer cannot constant-fold the interpreter back into
   the original program. Because `virt` runs *first* in the pipeline, its interpreter is then itself
   substituted, given bogus flow and flattened — the protections compound. Enabled with
   **`RUSTCLOAK_VM=1`**.
   *Round-1 scope (expanded in later rounds):* single-basic-block integer functions returning
   `i32`/`i64` — the integer mixers, key schedules and branchless checks that matter — using
   arithmetic, comparisons, `select` and the `i1`↔`iW` casts comparisons feed. Anything with memory,
   calls, loops/branches or other types is left native (correctness over coverage). Later rounds add
   branch opcodes (control flow), load/store opcodes (memory) and call opcodes.

**Per-build randomness.** All state numbers and keys come from a build seed. By default the seed is
random per build, so two builds of the same program differ (no two copies look alike); pass
`RUSTCLOAK_SEED=N` (an environment variable, so it works through `clang` and `rustc` alike) for a
reproducible build.

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
demoting such values — and all PHI nodes — to stack slots, and by hoisting every alloca into the
entry block, which dominates all cases (rustc places some allocas in non-entry blocks, and
`llvm.lifetime.end` then references one across blocks); the rewrite is always safe.

RustCloak is **architecture-independent** because it transforms LLVM IR, not machine code: the same
pass hardens x86-64 and AArch64 (and any LLVM target). The two emit different dispatcher machine
code — x86-64 a `sub imm; je` ladder, AArch64 a `cmp wREG; b.eq` compare-tree — but that is the
backend's choice; the IR transform is one implementation.

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

# Build-time flags (environment variables, so they work through clang and rustc alike):
#   RUSTCLOAK_SEED=N     reproducible build (default: random per build)
#   RUSTCLOAK_LAZY=1     decrypt each string on first use, not all at startup
#   RUSTCLOAK_ANTIEMU=1  bind string keys to a loader-set marker (defeats isolated emulation)
#   RUSTCLOAK_VM=1       virtualize eligible functions into custom-bytecode + interpreter
#   RUSTCLOAK_OFF=1      disable all transforms (safety off-switch; emit a normal build)
```

Self-checks (behaviour preserved + obfuscation present):

```sh
./test/build_and_test.sh                       # C: flatten + strenc + -O2 survival
RUSTCLOAK_NIGHTLY=nightly-2024-06-15 ./test/rust_demo.sh   # Rust: -Zllvm-plugins end to end
```

Both scripts are architecture-agnostic (set `RUSTCLOAK_TARGET=<triple>`, e.g. `aarch64-linux-gnu`,
to cross-compile instead of building natively). Correctness is checked at the IR level — markers
the pass injects, which survive `-O2`, and `strings` — not by a disassembly pattern, because the
dispatcher's machine code differs by arch.

Verified on **x86-64 and AArch64**: on the C and Rust demos the obfuscated binary produces
identical output, the secret string is absent from the file, and the control flow is flattened
(the dispatcher gives every block a random 32-bit state constant). The flattened output is also
recovered end-to-end by rust-deobf's deflattener on both arches — the red/blue loop.

## Rust integration notes

There are two ways to apply RustCloak to Rust, and `test/rust_demo.sh` uses the first, falling back
to the second:

1. **`rustc -Zllvm-plugins`** (convenient) — a **nightly** flag; the plugin must be built against the
   **same LLVM major version `rustc` ships** (rustc 1.81 / nightly-2024-06 use LLVM 18, matching
   `llvm-18-dev`). One caveat: rustc loads the plugin with `dlopen`, so the plugin's LLVM symbols
   must resolve against rustc's **bundled** LLVM — and **rustup toolchains statically link LLVM and
   hide most of its symbols**, so the load fails with `undefined symbol: ...` (e.g.
   `IRBuilderDefaultInserter`). This is a property of how that `rustc` was built, not of the
   architecture. It works with a `rustc` whose LLVM is dynamically linked / exports its symbols.

2. **`opt`-on-IR** (portable, any host/arch) — `rustc --emit=llvm-ir`, then the system `opt` (the
   same LLVM the plugin was built against) runs the passes on the real rustc IR:
   `opt -load-pass-plugin=build/libRustCloak.so -passes='strenc,function(subst,bogus,flatten)'`.
   This never depends on rustc's symbol exports and is the right path on stable or to obfuscate only
   part of a crate. Verified on **x86-64 and AArch64**: the secret string disappears from the IR and
   the flattening markers appear.

## Roadmap

- More opaque-predicate families and junk-code generators; protect the decrypt constructor itself.
- A `cargo` wrapper so a build is just `cargo rustcloak build`.
- Anti-debug / anti-tamper checks. (Anti-emulation via loader-bound keys and MBA substitution are
  now implemented — see `RUSTCLOAK_ANTIEMU` and transform 3.)
- Stronger anti-analysis state no constructor sets: keys derived at the first real syscall, or
  timing/TSC gates — the next step beyond what constructor-replay can answer.
- **Code virtualization — multi-round build-out.** Round 1 (done, `RUSTCLOAK_VM=1`) virtualizes
  single-block integer functions. Next rounds: branch opcodes (whole-CFG virtualization, loops),
  load/store opcodes (memory), call opcodes; then multiple randomized VM dispatch shapes and a
  bytecode whose encoding is itself per-build randomized/encrypted, so two builds share no VM.

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
