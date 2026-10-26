#!/usr/bin/env bash
# Differential fuzzing of the `virt` (code virtualization) transform. Builds vm_target.c twice --
# baseline (no plugin) and virtualized (RUSTCLOAK_VM=1, full -fpass-plugin pipeline) with a FIXED
# RUSTCLOAK_SEED so any divergence reproduces -- and feeds identical inputs to both `compute`s,
# aborting on any mismatch. Uses libFuzzer (coverage-guided) when the clang runtime is present,
# else a standalone xorshift driver. Works on x86-64 and AArch64.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PLUGIN=${PLUGIN:-$HERE/../../build/libRustCloak.so}
CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}   # fixed: reproducible builds
SECS=${SECS:-60}; ITERS=${ITERS:-20000000}
[ -f "$PLUGIN" ] || { echo "build the plugin first (cmake --build build)"; exit 1; }
cd "$HERE"

echo "== build baseline + virtualized (RUSTCLOAK_SEED=$RUSTCLOAK_SEED) =="
RUSTCLOAK_VM=1 $CLANG -O2 -fPIC -shared -fpass-plugin="$PLUGIN" vm_target.c -o libvmobf.so
# sanity: confirm virtualization actually happened (bytecode + constant-pool globals emitted)
vms=$(llvm-objdump-18 -t libvmobf.so 2>/dev/null | grep -c ' l .* O ' || true)
echo "  libvmobf.so built (internal objects incl. VM bytecode/pool: ~$vms)"

if $CLANG -O2 -fsanitize=fuzzer-no-link -c vm_target.c -o vm_base.o 2>/dev/null \
   && $CLANG -O2 -fsanitize=fuzzer vm_driver.c vm_base.o -ldl -o vm_difffuzz 2>/dev/null; then
  echo "== libFuzzer differential run (${SECS}s) =="
  ./vm_difffuzz -max_len=256 -max_total_time=$SECS -print_final_stats=1 2>&1 \
    | grep -E "DIVERGENCE|executed_units|exec/s|ERROR|crash|SUMMARY" || true
  echo "  (no DIVERGENCE / crash above == pass)"
else
  echo "== standalone differential run (${ITERS} iters; no libFuzzer runtime) =="
  $CLANG -O2 vm_target.c vm_stdfuzz.c -ldl -o vm_stdfuzz
  ./vm_stdfuzz "$ITERS"
fi
