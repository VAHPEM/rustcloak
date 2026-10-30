# VM eligibility — native-code holes: status & plan

`virt` leaves some calls native so the VM never mis-models an operation (`eligible()` / `virtCallee()`
in `src/Virt.cpp`, and `docs/VM-ISA.md`). *What stays native is a signal to an analyst*, so closing
these holes has real value. Each is a correctness hazard, so each lands only behind a differential
fuzz and the arch matrix — a short fuzz cannot disprove a call-ABI miscompile on its own.

## Done — typed-call dispatch (holes 1–3)
`OP_CALL` no longer goes through a uniform `i64(i64×6)` thunk. It now **switches on the callee index
and emits a real typed call per callee**, reconstructing args from the staged lane bits
(`ptr<-int`, `float<-low 32 bits`, `double<-bits`) and folding the result back into the lane. Because
each call is a normal typed LLVM call, the backend places integer/pointer/float args and the return
in the right ABI slots *by construction*. This closed, in one change:
- **#1 non-standard-width int returns** — any `iN` return zero-extends into the lane.
- **#2 >6 args** — now up to 8 (the argbuf width); stack args handled by the backend, not a hand ABI.
- **#3 float / double args and returns** — passed/returned in the FP class correctly.

`virtCallee` now accepts a direct, non-vararg, non-intrinsic callee with ≤8 lane-typed args and a
lane-typed/void return.

### Verification status (be precise about this)
- **AArch64 (AAPCS): PASS.** `difftest` 6/6; `compute` in the new call-heavy corpus
  `test/fuzz/vm_target3.c` (3 float args, 8 int args, mixed int/float/double/ptr args, float/double/
  long returns) confirmed virtualized; **4.79M-iteration** coverage-guided differential fuzz, zero
  divergence.
- **x86-64 SysV: PASS (verified directly).** Built the plugin natively on x86_64 Ubuntu 24.04
  (llvm-18.1.3) and ran difftest 6/6 + the `vm_target3` (float/XMM, 8 stacked args) and `vm_target4`
  (indirect) differentials -- zero divergence. This is the ABI most unlike AArch64 (float args in
  XMM, >6 args on the stack), so it was the key check.
- **Windows x64 (Win64): still pending** (no wine on the lab host); covered by CI or an x86-64
  Windows host. A longer multi-hour soak is optional insurance, not a blocker.

## Done — indirect calls (hole #4)
`OP_CALLV` holds the callee pointer in a register and the call site's `FunctionType` in a per-build
signature table; the interpreter switches on the signature index and makes a real typed indirect
call. `virtIndirectCall` accepts a non-vararg indirect call with <=8 lane-typed args and a
lane-typed/void return; a `ConstantExpr` callee stays native. Corpus `test/fuzz/vm_target4.c` drives
int(int,int) and float(float) indirect calls through virtualized trampolines.

Both the direct and indirect call switches store each arm's result straight into `reg[dst]` and
branch to a plain tail (no merge PHI), so nested re-virtualization -- which lowers every switch to a
branch chain -- has no cross-block PHI edge to invalidate.

Verification: AArch64 PASS -- difftest 6/6, combos 20/20 (incl. nested VM), 13.2M-iteration
differential fuzz on vm_target4, zero divergence. x86-64 SysV verified directly (difftest 6/6 +
vm_target3/vm_target4 differentials on x86_64 Ubuntu); Win64 pending (no wine locally).

## Nothing left open
All of eligible()'s call holes are closed. Any further work is on non-call ops (none currently
rejected that matter in practice) -- revisit only if a real target shows a recurring native island.
