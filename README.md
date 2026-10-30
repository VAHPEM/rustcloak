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

   With **`RUSTCLOAK_STRENC_SELFKEY=1`** the marker is taken one step further: instead of a
   constructor storing a per-build `MAGIC` constant, the constructor **computes** the marker at run
   time as an FNV-1a hash of the ciphertext itself (the encrypted string bytes, which are known at
   compile time, so the compile-time `MAGIC` is set to match). The key is then never a constant a
   static tool can read — to learn it, a tool must actually execute the hash over the real encrypted
   data. It also ties the key to the exact ciphertext, so editing the encrypted bytes changes the
   marker and corrupts every string (`test/selfkey.sh`).

3. **Instruction substitution — `subst` (`src/Subst.cpp`).** Replaces arithmetic/logic with longer
   equivalent expressions, in two equivalence-preserving layers. First, **mixed boolean-arithmetic
   (MBA)** identities — now *several per operator*, chosen by seed so no single pattern matches every
   rewrite: `a + b` → `(a^b)+2(a&b)` or `(a|b)+(a&b)`; `a ^ b` → `(a|b)−(a&b)` or `(a|b)&~(a&b)`;
   `a & b` → `(a|b)−(a^b)` or `a&~(a&~b)`; `a | b` → `(a&b)+(a^b)` or `a+b−(a&b)`; and the `a − b`
   duals. Second, an invertible **affine (permutation-polynomial) encoding** of add/sub: a per-op odd
   constant `A` and its modular inverse give `a + b = A⁻¹·(A·a + A·b) (mod 2^w)`, so the operation is
   carried out in an encoded domain a simplifier (arybo/SSPAM) must invert. `RUSTCLOAK_SUBST_DEPTH=N`
   (default 1, capped at 4) re-applies the rewrite N times — operators created in one round are
   rewritten in the next, so expressions nest to depth N (measured expansion ≈ 3× at depth 1, ≈ 20× at
   depth 3), and the nesting breaks up the clean affine pattern so it is not trivially folded back.

4. **Bogus control flow + opaque predicates — `bogus` (`src/Bogus.cpp`).** Splits blocks and guards
   the real path with an **opaque predicate** — a condition that is always true but that the compiler
   cannot fold away, because it is computed from a non-constant global. **Five always-true families**
   are mixed per block (the seed picks one), each proven always-true over all 32-bit inputs with z3,
   so a deobfuscator cannot pattern-match a single shape: `(x·(x+1)) & 1 == 0`, `(x² + x) & 1 == 0`,
   `(x² ^ x) & 1 == 0`, `(x | 1) & 1 == 1`, and `(x&1)·(x&1) == (x&1)`. Each guarded block gains a
   fake alternate path that never executes but clutters the control-flow graph. That fake path no
   longer stores to a dedicated sink global (a one-line grep/YARA signature) — it computes a
   **realistic hash/mix-shaped value from a live in-scope value and feeds it back into the flow
   through a PHI** the tail reads, anchored by a volatile *read* of module state so the optimizer
   keeps the branch rather than speculating it into a select.

   **Two-way opaque predicates (`RUSTCLOAK_BOGUS_TWOWAY=1`).** The one-way form above has a dead arm a
   prover can prune once it shows the predicate constant. The two-way form has *no dead arm*: it
   splits a block and routes a live integer value through a diamond whose two arms recompute that
   value by different (equivalent) expressions and feed a PHI the tail then uses, selected by a
   genuinely data-dependent predicate (a live value's low bit). Both arms are reachable and each
   carries a volatile read of module data folded as `& 0` — a no-op for the result, but a real side
   effect, so the optimizer will not speculate the arms away and collapse the diamond into a `select`.
   The branch therefore survives a `simplifycfg` pass (verified), there is no always-true constant to
   fold, and no volatile store-to-sink signature. See `test/twoway.sh`.

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
   *Scope (grows per round; correctness over coverage):* Round 1 single-basic-block integer
   functions; **round 2** control flow (multi-block, branches, **loops**, PHI nodes) via
   `JMP`/`JZ`/`JNZ` and SSA-destruction; **round 3** memory — loads, stores, `getelementptr`,
   pointers, mixed widths (i8/i16/i32/i64), so a real buffer routine virtualizes whole; **round 4
   hardens the VM itself** — the logical-opcode→byte map is a **seeded random permutation per build
   and per function**, so two builds share no VM instruction set and a deobfuscator cannot assume
   fixed opcode numbers (it must recover the map from the handlers); and the three **operand bytes
   (dst, a, b) are XOR-encrypted** with a per-build/per-function key, so the *whole* 4-byte
   instruction — register indices, pool indices and branch targets included — is build-specific and
   the interpreter decrypts each operand after fetch. Each width-sensitive opcode still carries its
   width in its two high bits; the bytecode and pool are mutable globals read through volatile loads.
   Direct **function calls** are virtualized too (round 6): `PUSHARG`/`CALL` opcodes stage the
   arguments and dispatch through a per-function callee-pointer table, so a function that calls
   helpers virtualizes whole (direct, non-vararg, non-intrinsic callees with ≤6 integer/pointer
   args). Left native: indirect/vararg/intrinsic calls, global references, floats, vectors. Verified
   behaviour-identical to native on x86-64, AArch64 and Windows x86-64 over a 20,000-iteration stress
   fold through real buffers, across seeds (each a different opcode map).

   **Selective virtualization.** Virtualization is the strongest transform but also the most
   expensive, so applying it to every eligible function taxes the whole program for protection only a
   few routines need. By default `RUSTCLOAK_VM=1` still virtualizes everything eligible; the scope can
   be narrowed so the VM's cost lands only where it matters: `RUSTCLOAK_VM_SELECTIVE=1` keeps only
   functions whose name looks security-sensitive (a built-in heuristic — `check`, `licen`, `crypt`,
   `encrypt`, `key`, `hash`, `auth`, `sign`, `serial`, `schedule`, …); `RUSTCLOAK_VM_ONLY=a,b`
   restricts to names containing those substrings; `RUSTCLOAK_VM_SKIP=a,b` is a denylist that wins in
   every mode; `RUSTCLOAK_VM_RATIO=P` keeps a seeded ~P% of the otherwise-chosen set; and
   `__attribute__((annotate("rustcloak_vm")))` on a function forces it to be virtualized in *any*
   mode. `test/select.sh` checks each mode virtualizes exactly the intended functions and that
   behaviour is preserved whatever the selection.

   **Encrypted jump-table dispatch (`RUSTCLOAK_VM_JMP=1`).** By default the interpreter dispatches
   with a `switch` on the opcode — the textbook shape a symbolic VM-lifter looks for first. In this
   mode the switch is replaced by an *encrypted jump table*: the opcode is run through a per-build
   affine permutation of 0..255 (`idx = (A·op + B) mod 256`, `A` odd so it is a bijection) that
   indexes a global table of block addresses, and control transfers by `indirectbr`. There is then no
   switch to pattern-match, and the opcode→handler mapping is scattered through the permuted table
   rather than sitting in readable `case` labels. Behaviour is identical; verified across the matrix.

   **Nested virtualization — VM-in-VM (`RUSTCLOAK_VM_NEST=1`).** The layer-0 interpreter is itself a
   function, so it can be virtualized a second time: its dispatch loop, opcode handlers and operand
   decode all become bytecode for a *second*, independently-encoded VM (a different opcode permutation
   and operand key). An analyst who reconstructs the outer VM finds, where the program logic should
   be, only another fetch-decode-dispatch loop to reverse — the multi-layer model of VMProtect /
   Themida. To make the interpreter re-eligible the second pass adds two opcodes the base VM never
   needs (`OP_GLOBAL` to materialise a referenced data global's address through a pointer table, and
   `OP_ALLOCA` for the interpreter's register-file stack slot) and first lowers the dispatch `switch`
   to a branch chain, de-volatilises the bytecode loads, and turns the unreachable default into a
   return. It is best-effort: an interpreter that still has an indirect callee-table call (i.e. the
   virtualized function made calls) is left as the correct single layer. On the single-call fixture
   the bytecode grows ~14× (it now encodes the whole interpreter); `test/nest.sh` confirms nesting
   engages and stays behaviour-identical on x86-64, AArch64 and Windows PE plus a differential fuzz.
   Nested code runs ~two orders of magnitude slower, so pair it with selective virtualization.

   **Anti-tamper bytecode integrity (`RUSTCLOAK_VM_INTEGRITY=1`).** On top of the per-build operand
   encryption, the interpreter can hash *its own bytecode* at run time (FNV-1a-64 over the blob, via
   the same volatile loads it executes) and XOR-fold the result into the operand-decryption keys. For
   an intact blob the hash matches a compile-time constant, the fold is zero, and the VM runs exactly
   as before; flip **any** bytecode byte and the hash changes, so every subsequent operand decode —
   register indices, pool indices, branch targets — comes out wrong and the VM diverges into garbage
   or crashes. Crucially there is **no `if (hash != expected)` branch** to locate and NOP: the check
   *is* the decryption. `test/tamper.sh` flips every byte of a function's bytecode and confirms the
   protected build catches 100% of single-byte flips where the unprotected build misses some.

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
#   RUSTCLOAK_HARDEN=1   one-switch strong preset: VM + integrity + jump-table + two-way bogus +
#                        runtime string keys + depth-2 MBA (not the ~100x-slower nested VM)
#   RUSTCLOAK_SEED=N     reproducible build (default: random per build)
#   RUSTCLOAK_SUBST_DEPTH=N  apply MBA substitution N times (1..4); deeper = larger expressions
#   RUSTCLOAK_LAZY=1     decrypt each string on first use, not all at startup
#   RUSTCLOAK_ANTIEMU=1  bind string keys to a loader-set marker (defeats isolated emulation)
#   RUSTCLOAK_STRENC_SELFKEY=1  derive that marker by hashing the ciphertext (key is never a constant)
#   RUSTCLOAK_STRENC_SYSCALLKEY=1  derive the key from time(NULL) at run time (Linux): correct
#                        on a real host, garbage under syscall-stubbing emulation
#   RUSTCLOAK_BOGUS_TWOWAY=1  two-way opaque predicates (both arms live, no prunable dead branch)
#   RUSTCLOAK_VM=1       virtualize eligible functions into custom-bytecode + interpreter
#   RUSTCLOAK_VM_SELECTIVE=1  virtualize only sensitive-named functions (not every eligible one)
#   RUSTCLOAK_VM_ONLY=a,b   virtualize only functions whose name contains a or b
#   RUSTCLOAK_VM_SKIP=a,b   never virtualize functions whose name contains a or b
#   RUSTCLOAK_VM_RATIO=P    virtualize a seeded ~P% of the otherwise-chosen functions
#   RUSTCLOAK_VM_JMP=1      dispatch via an encrypted indirectbr jump table, not a switch
#   RUSTCLOAK_VM_NEST=1     re-virtualize the interpreter itself (VM-in-VM; ~100x slower)
#   RUSTCLOAK_VM_INTEGRITY=1  VM self-hashes its bytecode; tampering corrupts the operand keys
#   RUSTCLOAK_OFF=1      disable all transforms (safety off-switch; emit a normal build)
```

Self-checks (behaviour preserved + obfuscation present):

```sh
./test/build_and_test.sh                       # C: flatten + strenc + -O2 survival
RUSTCLOAK_NIGHTLY=nightly-2024-06-15 ./test/rust_demo.sh   # Rust: -Zllvm-plugins end to end
./test/difftest.sh                             # behaviour: obfuscated == baseline (+ virt fuzz)
./test/matrix.sh                               # the whole matrix: ELF x64/ARM64 + Windows PE
./test/measure.sh                              # strength/cost per transform
./test/diversity.sh                            # same seed reproduces; different seeds diverge
./test/tamper.sh                               # VM integrity: every bytecode byte-flip is caught
./test/nest.sh                                 # nested VM-in-VM engages and stays correct
./test/combos.sh                               # every flag COMBINATION stays behaviour-correct
./test/select.sh ./test/selfkey.sh ./test/twoway.sh   # selective VM / runtime key / two-way bogus
RUSTDEOBF=../vahpem/rust-deobf ./test/redblue.sh   # run the real deobfuscator; report what it recovers
```

Both of the first two scripts are architecture-agnostic (set `RUSTCLOAK_TARGET=<triple>`, e.g.
`aarch64-linux-gnu`, to cross-compile instead of building natively). Correctness is checked at the
IR level — markers the pass injects, which survive `-O2`, and `strings` — not by a disassembly
pattern, because the dispatcher's machine code differs by arch.

`test/matrix.sh` is the cross-platform / cross-architecture gate. On a single Linux host it builds
every demo twice (baseline vs. `RUSTCLOAK_VM=1` full pipeline, fixed seed) and **runs both** on each
of three real targets, requiring byte-identical stdout and exit code, then differential-fuzzes the
VM on each:

| target        | format      | CPU     | how it runs          |
|---------------|-------------|---------|----------------------|
| `linux-x64`   | ELF         | x86-64  | native               |
| `linux-arm64` | ELF         | AArch64 | `qemu-aarch64-static`|
| `win-x64`     | PE (mingw)  | x86-64  | `wine`               |

A target whose toolchain or emulator is absent is reported `SKIP`, never a silent pass, so the
output always names exactly which `{OS-format, CPU}` pairs were exercised. The differential fuzzer
links the baseline and the virtualized `compute` into one static binary (`test/fuzz/vm_selfdiff.c`)
so it runs unchanged under the emulators — no `dlopen`, no libFuzzer runtime needed. On x86-64 the
coverage-guided libFuzzer differential (`test/fuzz/difffuzz_vm.sh`, driven by `difftest.sh`) runs
too.

Verified on **x86-64, AArch64, and Windows x86-64 (PE)**: on the C and Rust demos the obfuscated
binary produces identical output, the secret string is absent from the file, and the control flow is
flattened (the dispatcher gives every block a random 32-bit state constant). Across the stress path
(which exercises every VM opcode path — arithmetic, memory, calls, loops) all three targets fold to
the **same** checksum. The flattened output is also recovered end-to-end by rust-deobf's deflattener
on x86-64 and AArch64 — the red/blue loop.

## Red/blue measurement — run the real deobfuscator

Rather than proxy metrics (entropy, fold-survival), `test/redblue.sh` runs the actual counterpart
analysis toolkit, [rust-deobf](https://github.com/VAHPEM/rust-deobf), against RustCloak's own VM
output and reports what it recovers. Point `RUSTDEOBF` at a checkout and install its Python deps
(`lief`, `capstone<6`, `unicorn`, `z3`); otherwise it prints how to get them and skips. On the
single-function fixture `test/vm_one.c`:

| blue tool | technique | plain `virt` | `+VM_JMP` | `+INTEGRITY` | `+NEST` |
|-----------|-----------|:---:|:---:|:---:|:---:|
| `detect_vm.py` | static VM detection | not detected | — | — | — |
| `lift_vm.py` | static bytecode lift | not lifted | — | — | — |
| `devirt_emulate.py` | Unicorn emulation | **recovered** | **recovered** | **defeated** | **defeated** |

`RUSTCLOAK_HARDEN=1` turns the whole strong set on in one switch (integrity + jump-table + two-way
bogus + runtime string keys + depth-2 MBA), and a `HARDEN` VM build is itself not recovered by
`devirt_emulate.py` ("could not recover") — the integrity mode it includes is what defeats the
emulator. The reading: structural VM hardening (per-build randomized opcodes, encrypted operands, jump-table
dispatch) already defeats the **static** detector and lifter — but emulation observes the real
computation and reconstructs it regardless of structure, so plain `virt` and even jump-table
dispatch fall to `devirt_emulate.py`. The two hardening modes that *do* defeat the emulator here are
**bytecode integrity** (the operand keys become a run-time function of the bytecode hash, which the
devirtualizer's key-recovery does not model) and **nested virtualization** (the emulator recovers the
*inner* interpreter's program, not the original function). Emulation's ultimate counter is executing
the sample — which RustCloak deliberately does not try to block with anti-analysis runtime behaviour;
it answers emulation only where it can do so statically (the strenc `SELFKEY`/`ANTIEMU` loader-bound
keys). This is the honest state of the art, measured, not asserted.

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

Already shipped since the first cut (see the build-time flags above and `docs/VM-ISA.md`): whole-CFG
virtualization (branch opcodes, loops), memory load/store and call opcodes, scalar float (f32/f64)
opcodes, partial block-level virtualization of otherwise-ineligible functions, per-build randomized
synonym opcodes with XOR-encrypted operands, jump-table (`indirectbr`) dispatch, bytecode
self-integrity, and nested VM-in-VM. Anti-emulation via loader-bound / self-derived string keys
(`RUSTCLOAK_ANTIEMU`, `RUSTCLOAK_STRENC_SELFKEY`) and iterated MBA substitution are implemented.

Next, in order of leverage:

- **Adoption — `cargo rustcloak`.** One command hardens a crate (`tools/cargo-rustcloak`, `docs/CARGO.md`):
  a `RUSTC_WRAPPER` that injects the plugin into the primary package's crates only, so rustc still
  links and the output runs normally.
- **Key provenance over new ciphers.** Derive string/const keys at the first real syscall, or from a
  timing/TSC gate — the step beyond what constructor-replay can answer. Adding more cipher
  *algorithms* buys nothing: the red/blue measurement shows emulation defeats every static cipher
  equally, so what matters is a key the emulator cannot reproduce, not a stronger cipher.
- **Close the VM eligibility holes.** Indirect calls, calls with >6 args or float args currently stay
  native — and *what stays native is itself a signal to the analyst*.
- **Per-build randomized/encrypted bytecode encoding**, so two builds share no VM ISA at all.
- **More opaque-predicate families and junk-code generators; protect the decrypt constructor itself.**
- **Coverage.** A behavioural (run) matrix for Mach-O, not only object-level (`test/matrix_macho.sh`).

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
