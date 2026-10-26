#!/usr/bin/env bash
# Reproducibility + metamorphism invariant. For the full pipeline (RUSTCLOAK_VM=1 + -O2 plugin):
#   1. REPRODUCIBLE  -- two builds with the SAME RUSTCLOAK_SEED produce byte-identical obfuscated IR.
#   2. DIVERSE       -- two builds with DIFFERENT seeds produce substantially different IR
#      (different VM opcode maps/bytecode, different flattening state constants, different keys), so
#      no two shipped copies look alike.
#   3. EQUIVALENT    -- every such build, whatever the seed, behaves exactly like the unobfuscated
#      program, on x86-64 and (if available) AArch64 and Windows PE.
# Together: "two builds, different seed, same behaviour but different structure" -- a metamorphic
# obfuscator, and a guard against a seed accidentally leaking into behaviour.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
PLUGIN="$(pwd)/build/libRustCloak.so"
SRC=${SRC:-test/vm_demo.c}
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WINEDEBUG=-all WINEPREFIX=$WORK/wine
SA=0x1111111111 ; SB=0x2222222222
fails=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

irgen() { RUSTCLOAK_VM=1 RUSTCLOAK_SEED=$1 $CLANG -O2 -fno-discard-value-names -fpass-plugin=$PLUGIN \
            -emit-llvm -S "$SRC" -o "$2" 2>/dev/null; }

echo "== 1. reproducible: same seed -> identical IR =="
irgen $SA "$WORK/a1.ll"; irgen $SA "$WORK/a2.ll"
if cmp -s "$WORK/a1.ll" "$WORK/a2.ll"; then echo "  OK   same seed reproduces byte-identical IR"
else echo "  FAIL same seed differs"; fails=$((fails+1)); fi

echo "== 2. diverse: different seed -> different IR =="
irgen $SB "$WORK/b.ll"
if cmp -s "$WORK/a1.ll" "$WORK/b.ll"; then echo "  FAIL seeds A and B gave identical IR"; fails=$((fails+1))
else
  tot=$(wc -l < "$WORK/a1.ll"); dif=$(diff "$WORK/a1.ll" "$WORK/b.ll" | grep -cE '^[<>]')
  pct=$(awk "BEGIN{printf \"%.1f\", 100*$dif/$tot}")
  echo "  OK   seeds differ structurally: $dif/$tot IR lines change (${pct}%)"
  # require a meaningful amount of divergence, not a one-line fluke
  awk "BEGIN{exit !($dif > 0.1*$tot)}" || { echo "  FAIL divergence too small"; fails=$((fails+1)); }
fi

echo "== 3. equivalent: every seed behaves like the baseline =="
$CLANG -O2 "$SRC" -o "$WORK/base" 2>/dev/null
bn=$("$WORK/base"); bs=$("$WORK/base" stress)
check_run() { # name triple linker runner ext
  IFS='|' read -r name triple linker runner ext <<<"$1"
  local t=(); [ -n "$triple" ] && t=(--target="$triple")
  for seed in $SA $SB 0xdeadbeef; do
    RUSTCLOAK_VM=1 RUSTCLOAK_SEED=$seed $CLANG "${t[@]}" -O2 -fpass-plugin=$PLUGIN -c "$SRC" -o "$WORK/o.o" 2>/dev/null \
      && $linker "$WORK/o.o" -o "$WORK/o$ext" 2>/dev/null || { echo "  FAIL $name seed=$seed build"; fails=$((fails+1)); continue; }
    r1=$([ "$runner" = direct ] && "$WORK/o$ext" || $runner "$WORK/o$ext" 2>/dev/null | tr -d '\r')
    r2=$([ "$runner" = direct ] && "$WORK/o$ext" stress || $runner "$WORK/o$ext" stress 2>/dev/null | tr -d '\r')
    [ "$r1" = "$bn" ] && [ "$r2" = "$bs" ] || { echo "  FAIL $name seed=$seed behaviour differs"; fails=$((fails+1)); }
  done
  echo "  OK   $name: all seeds match baseline"
}
check_run "linux-x64||$CLANG|direct|"
command -v aarch64-linux-gnu-gcc >/dev/null && command -v qemu-aarch64-static >/dev/null \
  && check_run "linux-arm64|aarch64-linux-gnu|aarch64-linux-gnu-gcc -static|qemu-aarch64-static|" || echo "  SKIP linux-arm64"
command -v x86_64-w64-mingw32-gcc >/dev/null && command -v wine >/dev/null \
  && check_run "win-x64|x86_64-w64-windows-gnu|x86_64-w64-mingw32-gcc -static|wine|.exe" || echo "  SKIP win-x64"

echo
[ $fails = 0 ] && echo "DIVERSITY PASS" || { echo "DIVERSITY FAILED ($fails)"; exit 1; }
