# CLAUDE.md — RustCloak

LLVM new-pass-manager plugin that hardens programs against reverse engineering at the LLVM-IR
level. **Two tiers:** the Apache-2.0 **core** in `src/` (function passes `flatten`, `subst`, `bogus`,
`constenc`; module pass `strenc`; plus `Plugin.cpp` registration and `RustCloak.h` seeded `anon()`
names + per-build `rng`), and the AGPL-or-commercial **premium** tier in `premium/` (function passes
`virt`, `partial`; module passes `antitamper`, `license`, `imphide`). Premium builds in by default;
`-DRUSTCLOAK_PREMIUM=OFF` yields a core-only Apache-2.0 plugin. The premium pass declarations in
`RustCloak.h` and their registration in `Plugin.cpp` are guarded by `#ifdef RUSTCLOAK_PREMIUM`; the
core never includes or links premium. It is the red/blue counterpart to **rust-deobf** and a
test-case generator for it, so **behaviour must be preserved exactly**.

## Build + test run on the KALI VM, not the cloud container
The cloud container has `clang-18`/`opt-18` but **not** `llvm-18-dev` (no CMake config, no headers)
→ the plugin cannot be built there. The toolchain (`clang-18`, `opt-18`, `llvm-config-18`, `cmake`,
`ninja`) lives on the **ARM64 Kali VM**, driven through the `dualvm` package on the Mac
(`dual-vm-ai-agent/`; read its CLAUDE.md). From a Cowork session, push sources to Kali (base64 over
`dualvm.shell.run_script`) and build there:

```
cmake -S . -B build -G Ninja -DLLVM_DIR="$(llvm-config-18 --cmakedir)"
cmake --build build          # -> build/libRustCloak.so  (premium tier ON by default)
# core-only (Apache-2.0, no VM/antitamper/license/imphide):  add -DRUSTCLOAK_PREMIUM=OFF
```

Native target is **aarch64 ELF**. State which arch you actually ran — don't assume another
(x86-64/PE/Mach-O need qemu-user or cross builds; see `test/matrix.sh`).

If the Kali image has clang-21/libstdc++-16 installed alongside clang-18, `clang++-18` picks the
newer libstdc++ headers and fails on C++; pin it with
`CLANGXX="clang++-18 --gcc-install-dir=/usr/lib/gcc/aarch64-linux-gnu/14"` for the C++ corpus.

`rustc -Zllvm-plugins=<plugin>` does NOT load this plugin: rustc's driver exports only ~375 LLVM
symbols (0 IRBuilder), the plugin needs ~140 it does not export, and that set shifts every release —
not fixable from the plugin side and high-maintenance if hacked. Obfuscate emitted IR with `opt`
instead (`test/rust_e2e.sh`): same LLVM major, independent of rustc's exports, low maintenance.

## Correctness gate — the differential tests MUST pass after any pass change
```
test/difftest.sh             # baseline vs full -O2 pipeline (+RUSTCLOAK_VM); exit code + stdout
test/fuzz/difffuzz_vm.sh     # coverage-guided baseline-vs-virt fuzzer; oracle = equal outputs
test/corpus/run.sh           # C/C++/Rust corpus, eager+lazy, + no-plaintext-leak check
test/measure.sh              # cost (size/runtime) vs difficulty (handlers, entropy, fold-survival)
test/matrix.sh               # per-arch/format object + behaviour (aarch64 run, x86-64 via qemu)
test/diversity.sh            # two different RUSTCLOAK_SEED builds: same behaviour, different bytes
```
A fixed `RUSTCLOAK_SEED` makes a build reproducible. "Measure before you conclude."

## Build-time flags (env, read via getenv)
| flag | effect |
|---|---|
| `RUSTCLOAK_SEED=<u64>` | fixed per-build seed (unset = random each build) |
| `RUSTCLOAK_OFF=1` | disable the automatic `-O2` (`OptimizerLast`) hookup |
| `RUSTCLOAK_VM=1` | enable `virt` (code virtualization); off by default (~18x runtime) |
| `RUSTCLOAK_VM_ONLY=a,b` | virtualize only functions whose name contains a token |
| `RUSTCLOAK_VM_INLINE=1` | inline tiny leaf callees before virtualizing |
| `RUSTCLOAK_VM_INTEGRITY=1` | bytecode anti-tamper (checksum folded into the operand keys) |
| `RUSTCLOAK_SUBST_DEPTH=N` | iterate MBA substitution to depth N (1..4) |
| `RUSTCLOAK_LAZY=1` | decrypt strings on first use, not at startup |
| `RUSTCLOAK_STRENC_CIPHER=1` | per-string LCG keystream instead of linear `seed+i` |
| `RUSTCLOAK_STRENC_CALLSITE=1` | decrypt into a sibling buffer; the global stays ciphertext |
| `RUSTCLOAK_ANTIEMU=1` | key decryption on a ctor-set marker (defeats isolated emulation) |
| `RUSTCLOAK_STRENC_CHAIN=1` | chain per-string keys via FNV of the previous plaintext (ordered decrypt) |
| `RUSTCLOAK_STRENC_SYSCALLKEY=1` | key decryption on a real syscall (time(NULL)); defeats constructor-replay emulation (Linux-first) |
| `RUSTCLOAK_CONSTENC=1` | hide integer literals as `C ^ opaqueZero(arg)` |
| `RUSTCLOAK_MBA_PERM=1` | wrap integer results in an invertible xor-shift permutation (GF(2) MBA) |
| `RUSTCLOAK_VM_PARTIAL=1` | outline an eligible block region of an ineligible function and virtualize it |
| `RUSTCLOAK_ANTITAMPER=1` | .text-section self-integrity; **requires** `tools/antitamper_patch.py <bin>` post-link |
| `RUSTCLOAK_LICENSE=<hex>` | license gate: binary runs correctly only with matching `RC_KEY` env at runtime |
| `RUSTCLOAK_HIDE_IMPORTS=a,b` | resolve named imports via `dlsym` (encrypted name); removes them from the import table (link `-ldl`) |

## virt invariants (the fragile pass — see the `binary-analysis` / `vuln-research` skills)
- Registers are a uniform i64 lane; integers kept zero-extended, scalar f32/f64 kept as raw bits.
  Width-sensitive opcodes carry a 2-bit width code `{8,16,32,64}` (for float ops 2=f32, 3=f64). Any
  other integer width is left native by `eligible()`. Dispatch is an `indirectbr` through a handler-
  address table (not a switch). `strenc` encrypts private constant arrays of i8/i16/i32/i64, not
  only i8 strings.
- Every constant the interpreter reads (literals, `trunc` masks, folded GEP offsets) must enter the
  pool **before** the `OP_CONST` batch is emitted — the constant-pool bug class lived here.
- After editing, re-read for boundary / width / arch assumptions, *then* run `difftest.sh`.

## Git (org VAHPEM)
Author commits as **Ve (VAHPEM) `<ve0912084386@gmail.com>`**, Claude as `Co-Authored-By`. Ve runs
`git push` from the Mac terminal — the Cowork device shell has **no GitHub credentials**, so don't
`git fetch`/`pull` from here. Never commit `.env`, SSH keys, or `.ssh_keys/`.

> Cowork note: `device_commit_files` re-writing an existing path can be masked by a stale mount
> cache. Writing to a new path then `mv`-ing over the target, or a `python` in-place edit of the
> mounted file, writes through reliably.
