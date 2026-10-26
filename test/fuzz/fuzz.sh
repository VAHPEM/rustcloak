#!/usr/bin/env bash
# Differential fuzzing of RustCloak: compile target.c three ways -- baseline, eager-obfuscated,
# lazy-obfuscated -- and feed the same inputs to all three, aborting on any output divergence. A
# clean run over millions of inputs is strong evidence the obfuscation preserves behaviour.
# Uses libFuzzer (coverage-guided) when the clang runtime is present; otherwise a standalone
# random driver. Works on x86-64 and AArch64.
set -uo pipefail
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}   # fixed seed: reproducible obfuscation
HERE="$(cd "$(dirname "$0")" && pwd)"
PLUGIN=${PLUGIN:-$HERE/../../build/libRustCloak.so}
CLANG=${CLANG:-clang-18}
ITERS=${ITERS:-20000000}; SECS=${SECS:-60}
[ -f "$PLUGIN" ] || { echo "build the plugin first (cmake --build build)"; exit 1; }
cd "$HERE"
echo "== build baseline / eager-obf / lazy-obf =="
$CLANG -O2 -fPIC -shared -fpass-plugin="$PLUGIN" target.c -o libobf.so
RUSTCLOAK_LAZY=1 $CLANG -O2 -fPIC -shared -fpass-plugin="$PLUGIN" target.c -o liblazy.so
echo "  string leak: obf=$(strings libobf.so | grep -c 'state::')  lazy=$(strings liblazy.so | grep -c 'state::')  (expect 0 0)"

if $CLANG -O2 -fsanitize=fuzzer-no-link -c target.c -o base.o 2>/dev/null \
   && $CLANG -O2 -fsanitize=fuzzer driver.c base.o -ldl -o difffuzz 2>/dev/null; then
  echo "== libFuzzer differential run (${SECS}s) =="
  ./difffuzz -max_len=256 -max_total_time=$SECS -print_final_stats=1 2>&1 \
    | grep -E "DIVERGENCE|executed_units|exec_per_sec|ERROR|crash" || true
  echo "  (no DIVERGENCE / crash above == pass)"
else
  echo "== standalone differential run (${ITERS} iters; no libFuzzer runtime) =="
  $CLANG -O2 target.c stdfuzz.c -ldl -o stdfuzz
  ./stdfuzz "$ITERS"
fi
