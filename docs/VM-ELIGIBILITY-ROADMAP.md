# VM eligibility — plan for closing the native-code holes

`virt` deliberately leaves some functions/instructions native so the VM never mis-models an operation
(see `eligible()` and `virtCallee()` in `src/Virt.cpp`, and the eligibility section of
`docs/VM-ISA.md`). *What stays native is itself a signal to an analyst* ("the thing it refused to
virtualize is the interesting thing"), so closing these holes has real value — but each one is a
correctness hazard, and a **short** differential-fuzz run cannot disprove a call-ABI miscompile
(random byte inputs rarely drive a specific arg-count/arg-type path through the folded `compute`).
So this is a plan with the traps identified, to be implemented one hole at a time, each behind a
**multi-hour** `difffuzz_vm.sh` soak on a call-heavy corpus and the full `matrix.sh` across arches.

## Current CALL restriction (`virtCallee`)
Virtualizes only a **direct**, non-vararg, non-intrinsic callee with **≤6 integer/pointer args** and a
void/pointer/standard-width-int return, because `OP_CALL` dispatches through a uniform `i64(i64 x6)`
thunk (all args in registers on SysV/AAPCS). Left native: float args, >6 args, indirect calls,
non-standard return widths.

## Holes, in increasing difficulty

### 1. Non-standard integer return width (lowest risk)
A callee returning e.g. `i128`/`i48` is rejected only because the CALL handler has no width slot to
re-zero-extend. Lower-risk fix: for an `iN` return with N outside {8,16,32,64}, widen to the next
standard width in the thunk and mask on return. Trap: signedness — only re-zero-extend; a signed use
re-reads via SEXT already in the stream. Verifiable with a targeted corpus of odd-width returns.

### 2. Calls with >6 integer/pointer args
Needs arg staging beyond the 6-register thunk. Two options: (a) emit a per-arity thunk
`i64(i64 x N)`; (b) spill args 7+ to a small per-call stack buffer the thunk reads. Trap: the thunk
must match the platform ABI for stack args exactly (alignment, right-to-left on SysV). Verify per-arch
(SysV vs AAPCS vs Win64) — this is where an untested arch bites.

### 3. Calls with float/double args
The register lane holds raw bits; the current thunk passes GPR-class args only. Float args go in the
SSE/FP registers, a different ABI class, so a uniform integer thunk mis-passes them. Fix: dispatch
`OP_CALL` through the **callee's real `FunctionType`** (the callee-table already holds the real
pointer) instead of a uniform thunk — emit a typed call per callee. This is the clean general fix and
also subsumes holes 1–2, but it is a structural change to how `OP_CALL` is generated (Virt.cpp ~824)
and handled (~1106). Trap: the interpreter must reconstruct exact arg types/order from the bytecode;
get the FP/GPR class split wrong and it silently mis-passes on exactly the inputs a short fuzz misses.

### 4. Indirect calls (highest risk)
The callee is a runtime value, not a table index. Needs an `OP_CALLV` that calls a `reg`-held pointer
through a known `FunctionType`, plus a way to encode that type. Trap: without the callee's type the
VM cannot build the call; recovering it from the call site is doable but fragile. Do last.

## Recommended sequence
1 → 2 → 3 (the typed-call rewrite, which absorbs 1–2) → 4. After each: re-read for width/ABI/arch
assumptions, then `difftest.sh`, then a **soak** `SECS=3600 difffuzz_vm.sh` on both corpora on the
Kali VM, then `matrix.sh` (x86-64 + AArch64 + PE). Add a `VALIDATION`-style round note per step. Do
**not** relax `eligible()`/`virtCallee()` without that soak — the VM-ISA's "reject so we never
mis-model" invariant is the whole correctness story.
