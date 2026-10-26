#!/usr/bin/env bash
# Nested-virtualization (VM-in-VM) test for RUSTCLOAK_VM_NEST. Verifies that re-virtualizing the
# layer-0 interpreter (a) actually engages -- the bytecode grows many-fold because it now encodes the
# whole interpreter, and a second differently-encoded VM dispatches it -- and (b) stays behaviour-
# identical on x86-64, AArch64 (qemu) and Windows PE (wine), plus a small differential fuzz.
#
# Nested execution is ~two orders of magnitude slower than native, so this uses the tiny single-call
# fixture (test/vm_one.c) and a modest fuzz budget; it is a correctness + engagement gate, not a soak.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
FUZZ_ITERS=${FUZZ_ITERS:-4000}
PLUGIN="$(pwd)/build/libRustCloak.so"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WINEDEBUG=-all WINEPREFIX=$WORK/wine
fails=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

echo "== nesting engaged? (bytecode must grow many-fold) =="
$CLANG -O1 -fno-discard-value-names -emit-llvm -S test/vm_one.c -o "$WORK/one.ll" 2>/dev/null
env RUSTCLOAK_VM=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' "$WORK/one.ll" -S 2>/dev/null > "$WORK/s1.ll"
env RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' "$WORK/one.ll" -S 2>/dev/null > "$WORK/s2.ll"
b1=$(python3 test/opcode_entropy.py "$WORK/s1.ll" | grep -oE 'bytecode_bytes=[0-9]+' | cut -d= -f2)
b2=$(python3 test/opcode_entropy.py "$WORK/s2.ll" | grep -oE 'bytecode_bytes=[0-9]+' | cut -d= -f2)
vg=$(grep -cE 'internal global \[[0-9]+ x ptr\]' "$WORK/s2.ll")
echo "  layer-0 bytecode=$b1 bytes ; nested bytecode=$b2 bytes ; global-table=$vg"
if [ "${b2:-0}" -ge $(( ${b1:-1} * 3 )) ] && [ "${vg:-0}" -ge 1 ]; then echo "  OK   nesting engaged (${b2} >= 3x ${b1}, global table present)"
else echo "  FAIL nesting did not engage"; fails=$((fails+1)); fi

echo "== behaviour identical (base vs NEST) across targets =="
INPUTS="0x12345678 7 4242 0 0xffffffff"
# target: name|triple|linker|runner|ext
run_target() {
  IFS='|' read -r name triple linker runner ext <<<"$1"
  local bo="$WORK/${name}_b.o" vo="$WORK/${name}_n.o" bx="$WORK/${name}_b$ext" vx="$WORK/${name}_n$ext"
  local t=(); [ -n "$triple" ] && t=(--target="$triple")
  $CLANG "${t[@]}" -O2 -c test/vm_one.c -o "$bo" 2>/dev/null && $linker "$bo" -o "$bx" 2>/dev/null || { echo "  SKIP $name (baseline build)"; return; }
  if ! RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 $CLANG "${t[@]}" -O2 -fpass-plugin="$PLUGIN" -c test/vm_one.c -o "$vo" 2>/dev/null || ! $linker "$vo" -o "$vx" 2>/dev/null; then
    echo "  FAIL $name: nested build"; fails=$((fails+1)); return; fi
  local bad=0
  for y in $INPUTS; do
    bb=$([ "$runner" = direct ] && "$bx" $y || $runner "$bx" $y 2>/dev/null | tr -d '\r')
    nn=$([ "$runner" = direct ] && "$vx" $y || $runner "$vx" $y 2>/dev/null | tr -d '\r')
    [ "$bb" = "$nn" ] || { echo "  FAIL $name [y=$y]: base=$bb nest=$nn"; bad=1; }
  done
  [ $bad = 0 ] && echo "  OK   $name: base == nest on all inputs" || fails=$((fails+1))
}
run_target "linux-x64||$CLANG|direct|"
command -v aarch64-linux-gnu-gcc >/dev/null && command -v qemu-aarch64-static >/dev/null \
  && run_target "linux-arm64|aarch64-linux-gnu|aarch64-linux-gnu-gcc -static|qemu-aarch64-static|" \
  || echo "  SKIP linux-arm64 (toolchain)"
command -v x86_64-w64-mingw32-gcc >/dev/null && command -v wine >/dev/null \
  && run_target "win-x64|x86_64-w64-windows-gnu|x86_64-w64-mingw32-gcc -static|wine|.exe" \
  || echo "  SKIP win-x64 (toolchain)"

echo "== nested differential fuzz (vm_target; call-fns fall back to single layer) =="
$CLANG -O2 -Dcompute=compute_base -c test/fuzz/vm_target.c -o "$WORK/fb.o" 2>/dev/null
RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 $CLANG -O2 -fpass-plugin="$PLUGIN" -Dcompute=compute_virt -c test/fuzz/vm_target.c -o "$WORK/fv.o" 2>/dev/null
$CLANG -O2 -c test/fuzz/vm_selfdiff.c -o "$WORK/fd.o" 2>/dev/null
$CLANG "$WORK/fb.o" "$WORK/fv.o" "$WORK/fd.o" -o "$WORK/fz" 2>/dev/null
out=$("$WORK/fz" "$FUZZ_ITERS"); echo "  $out"
echo "$out" | grep -q '^OK:' || { echo "  FAIL fuzz divergence"; fails=$((fails+1)); }

echo
[ $fails = 0 ] && echo "NEST PASS" || { echo "NEST FAILED ($fails)"; exit 1; }
