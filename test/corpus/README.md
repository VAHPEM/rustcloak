# Corpus + differential fuzzing

Beyond the single `test/demo.c`, these exercise RustCloak on varied code and verify it preserves
behaviour across many inputs.

- `run.sh [target-triple]` — obfuscate three varied programs (C with recursion/switch/fn-ptr
  tables, C++ with exceptions + virtual dispatch, Rust with enums/iterators/HashMap) in eager and
  lazy modes and check the output matches the baseline with no string leak. Native = build+run;
  a target triple = IR-level check only.
- `../fuzz/fuzz.sh` — **differential fuzzing**: compile one target three ways (baseline /
  eager-obf / lazy-obf) and feed identical inputs to all three, aborting on any divergence.
  Coverage-guided with libFuzzer when available, else a standalone random driver. Verified clean
  over 13.4M inputs on AArch64 (Kali) and millions on x86-64.
