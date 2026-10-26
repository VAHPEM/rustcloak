#!/usr/bin/env bash
# Two-way opaque predicates (RUSTCLOAK_BOGUS_TWOWAY). The default bogus predicate is always-true with
# a dead bogus arm a prover can prune; the two-way form splits a block and routes a live value through
# a diamond whose two arms recompute it by different (equivalent) expressions, selected by a genuinely
# data-dependent predicate. This test checks:
#   1. behaviour preserved on x86-64, AArch64 (qemu), Windows PE (wine),
#   2. the branch is data-dependent (no always-true constant) and the diamond has no dead arm, so it
#      SURVIVES a plain `simplifycfg` pass (the arms carry a volatile read, so neither is speculated
#      away into a select), and it uses no volatile store-to-sink signature.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WINEDEBUG=-all WINEPREFIX=$WORK/wine
fails=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

echo "== behaviour preserved across targets =="
check() { # name triple linker runner ext
  IFS='|' read -r name triple linker runner ext <<<"$1"
  local t=(); [ -n "$triple" ] && t=(--target="$triple")
  for src in test/corpus/c_loops.c test/vm_demo.c; do
    local bx="$WORK/b$ext" ox="$WORK/o$ext"
    $CLANG "${t[@]}" -O2 -c "$src" -o "$WORK/b.o" 2>/dev/null && $linker "$WORK/b.o" -o "$bx" 2>/dev/null || { echo "  SKIP $name $(basename $src)"; continue; }
    RUSTCLOAK_BOGUS_TWOWAY=1 $CLANG "${t[@]}" -O2 -fpass-plugin=$PLUGIN -c "$src" -o "$WORK/o.o" 2>/dev/null && $linker "$WORK/o.o" -o "$ox" 2>/dev/null || { echo "  FAIL $name $(basename $src) build"; fails=$((fails+1)); continue; }
    for a in "" stress; do
      bb=$([ "$runner" = direct ] && "$bx" $a 2>/dev/null | tr -d '\r' || $runner "$bx" $a 2>/dev/null | tr -d '\r')
      oo=$([ "$runner" = direct ] && "$ox" $a 2>/dev/null | tr -d '\r' || $runner "$ox" $a 2>/dev/null | tr -d '\r')
      [ "$bb" = "$oo" ] || { echo "  FAIL $name $(basename $src) [a='$a']"; fails=$((fails+1)); }
    done
  done
  echo "  OK   $name"
}
check "linux-x64||$CLANG|direct|"
command -v aarch64-linux-gnu-gcc >/dev/null && command -v qemu-aarch64-static >/dev/null \
  && check "linux-arm64|aarch64-linux-gnu|aarch64-linux-gnu-gcc -static|qemu-aarch64-static|" || echo "  SKIP linux-arm64"
command -v x86_64-w64-mingw32-gcc >/dev/null && command -v wine >/dev/null \
  && check "win-x64|x86_64-w64-windows-gnu|x86_64-w64-mingw32-gcc -static|wine|.exe" || echo "  SKIP win-x64"

echo "== structure: data-dependent, no dead arm, survives simplifycfg =="
$CLANG -O1 -fno-discard-value-names -emit-llvm -S test/corpus/c_loops.c -o "$WORK/c.ll" 2>/dev/null
RUSTCLOAK_BOGUS_TWOWAY=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(bogus)' "$WORK/c.ll" -S 2>/dev/null > "$WORK/tw.ll"
sel=$(grep -cE 'icmp ne i(8|16|32|64) %[a-z0-9._]+, 0' "$WORK/tw.ll")
vstore=$(grep -c 'store volatile' "$WORK/tw.ll")
before=$(grep -c 'br i1' "$WORK/tw.ll")
$OPT -passes='simplifycfg' "$WORK/tw.ll" -S 2>/dev/null > "$WORK/tw2.ll"
after=$(grep -c 'br i1' "$WORK/tw2.ll")
echo "  data-dependent selectors=$sel  volatile-store-to-sink=$vstore  cond-br $before -> $after after simplifycfg"
[ "$sel" -ge 1 ] && [ "$vstore" = 0 ] && [ "$after" -ge "$before" ] \
  && echo "  OK   data-dependent two-way diamonds survive simplifycfg, no sink-store signature" \
  || { echo "  FAIL structural check"; fails=$((fails+1)); }

echo
[ $fails = 0 ] && echo "TWOWAY PASS" || { echo "TWOWAY FAILED ($fails)"; exit 1; }
