#!/usr/bin/env bash
# Combinatorial correctness gate: build each test program under many COMBINATIONS of RustCloak's
# flags and require byte-identical output to the unobfuscated baseline. Interaction bugs between
# transforms (e.g. two-way bogus + flatten, nested VM + integrity, selective + jump-table) live here,
# not in any single-feature test. Nested combos use only the fast fixtures (nested VM is ~100x
# slower, so the heavy vm_demo stress path is skipped for them). Set ARCHES="arm64 win" to also run
# the maximal combos cross-architecture (qemu / wine).
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; CLANGXX=${CLANGXX:-clang++-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN="$(pwd)/build/libRustCloak.so"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WINEDEBUG=-all WINEPREFIX=$WORK/wine
fails=0; n=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

clang-18 -O2 test/vm_demo.c -o "$WORK/d_base" 2>/dev/null
clang-18 -O2 test/vm_one.c -o "$WORK/o_base" 2>/dev/null
clang-18 -O2 test/corpus/c_loops.c -o "$WORK/c_base" 2>/dev/null
clang-18 -O2 test/vm_nested.c -o "$WORK/n_base" 2>/dev/null
DN=$("$WORK/d_base"); DS=$("$WORK/d_base" stress)
O7=$("$WORK/o_base" 7); O0=$("$WORK/o_base" 0); CL=$("$WORK/c_base"); NN=$("$WORK/n_base" a b)

one() { # label heavy(0/1) env...
  local label=$1 heavy=$2; shift 2; n=$((n+1)); local bad=0
  env "$@" $CLANG -O2 -fpass-plugin=$PLUGIN test/vm_one.c -o "$WORK/o" 2>/dev/null \
    && { [ "$("$WORK/o" 7)" = "$O7" ] && [ "$("$WORK/o" 0)" = "$O0" ] || { echo "  FAIL $label: vm_one"; bad=1; }; } \
    || { echo "  FAIL $label: vm_one build"; bad=1; }
  env "$@" $CLANG -O2 -fpass-plugin=$PLUGIN test/corpus/c_loops.c -o "$WORK/c" 2>/dev/null \
    && { [ "$("$WORK/c")" = "$CL" ] || { echo "  FAIL $label: c_loops"; bad=1; }; } \
    || { echo "  FAIL $label: c_loops build"; bad=1; }
  env "$@" $CLANG -O2 -fpass-plugin=$PLUGIN test/vm_nested.c -o "$WORK/n" 2>/dev/null \
    && { [ "$("$WORK/n" a b)" = "$NN" ] || { echo "  FAIL $label: vm_nested"; bad=1; }; } \
    || { echo "  FAIL $label: vm_nested build"; bad=1; }
  if [ "$heavy" = 1 ]; then
    env "$@" $CLANG -O2 -fpass-plugin=$PLUGIN test/vm_demo.c -o "$WORK/d" 2>/dev/null \
      && { [ "$("$WORK/d")" = "$DN" ] && [ "$("$WORK/d" stress)" = "$DS" ] || { echo "  FAIL $label: vm_demo"; bad=1; }; } \
      || { echo "  FAIL $label: vm_demo build"; bad=1; }
  fi
  [ $bad = 0 ] && echo "  OK   $label" || fails=$((fails+1))
}

echo "== non-nested combos (incl. vm_demo stress) =="
one "VM"               1 RUSTCLOAK_VM=1
one "VM+JMP"           1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_JMP=1
one "VM+INTEGRITY"     1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_INTEGRITY=1
one "VM+JMP+INTEGRITY" 1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_INTEGRITY=1
one "VM+SELECTIVE"     1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_SELECTIVE=1
one "VM+RATIO50"       1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_RATIO=50
one "VM+SUBST_DEPTH3"  1 RUSTCLOAK_VM=1 RUSTCLOAK_SUBST_DEPTH=3
one "VM+BOGUS_TWOWAY"  1 RUSTCLOAK_VM=1 RUSTCLOAK_BOGUS_TWOWAY=1
one "VM+STRENC_SELFKEY" 1 RUSTCLOAK_VM=1 RUSTCLOAK_STRENC_SELFKEY=1
one "VM+ANTIEMU"       1 RUSTCLOAK_VM=1 RUSTCLOAK_ANTIEMU=1
one "VM+LAZY+CIPHER"   1 RUSTCLOAK_VM=1 RUSTCLOAK_LAZY=1 RUSTCLOAK_STRENC_CIPHER=1
one "VM+CALLSITE"      1 RUSTCLOAK_VM=1 RUSTCLOAK_STRENC_CALLSITE=1
one "ALL-no-nest"      1 RUSTCLOAK_VM=1 RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_INTEGRITY=1 RUSTCLOAK_BOGUS_TWOWAY=1 RUSTCLOAK_SUBST_DEPTH=2 RUSTCLOAK_STRENC_SELFKEY=1

echo "== nested combos (fast fixtures only) =="
one "VM+NEST"               0 RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1
one "VM+NEST+INTEGRITY"     0 RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_INTEGRITY=1
one "VM+NEST+JMP"           0 RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_JMP=1
one "VM+NEST+SEL+TWOWAY"    0 RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_SELECTIVE=1 RUSTCLOAK_BOGUS_TWOWAY=1
one "ALL-with-nest"        0 RUSTCLOAK_VM=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_INTEGRITY=1 RUSTCLOAK_BOGUS_TWOWAY=1 RUSTCLOAK_SUBST_DEPTH=2 RUSTCLOAK_STRENC_SELFKEY=1

# optional cross-arch pass of the maximal combos
NO_NEST="RUSTCLOAK_VM=1 RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_INTEGRITY=1 RUSTCLOAK_BOGUS_TWOWAY=1 RUSTCLOAK_SUBST_DEPTH=2 RUSTCLOAK_STRENC_SELFKEY=1"
arch_one() { # label triple linker runner ext flags heavy
  local lbl=$1 tr=$2 ln=$3 rn=$4 ext=$5 flags=$6 heavy=$7; n=$((n+1)); local bad=0
  env $flags $CLANG -O2 --target=$tr -fpass-plugin=$PLUGIN -c test/vm_one.c -o "$WORK/x.o" 2>/dev/null && $ln "$WORK/x.o" -o "$WORK/x$ext" 2>/dev/null \
    && { r=$([ "$rn" = direct ] && "$WORK/x$ext" 7 || $rn "$WORK/x$ext" 7 2>/dev/null | tr -d '\r'); [ "$r" = "$O7" ] || { echo "  FAIL $lbl: vm_one"; bad=1; }; } || { echo "  FAIL $lbl: vm_one build"; bad=1; }
  if [ "$heavy" = 1 ]; then
    env $flags $CLANG -O2 --target=$tr -fpass-plugin=$PLUGIN -c test/vm_demo.c -o "$WORK/d.o" 2>/dev/null && $ln "$WORK/d.o" -o "$WORK/d$ext" 2>/dev/null \
      && { s=$([ "$rn" = direct ] && "$WORK/d$ext" stress || $rn "$WORK/d$ext" stress 2>/dev/null | tr -d '\r'); [ "$s" = "$DS" ] || { echo "  FAIL $lbl: vm_demo stress"; bad=1; }; } || { echo "  FAIL $lbl: vm_demo build"; bad=1; }
  fi
  [ $bad = 0 ] && echo "  OK   $lbl" || fails=$((fails+1))
}
for a in ${ARCHES:-}; do
  echo "== cross-arch maximal combos: $a =="
  case "$a" in
    arm64) command -v aarch64-linux-gnu-gcc >/dev/null && command -v qemu-aarch64-static >/dev/null \
             && { arch_one "arm64 ALL-no-nest" aarch64-linux-gnu "aarch64-linux-gnu-gcc -static" qemu-aarch64-static "" "$NO_NEST" 1
                  arch_one "arm64 ALL+nest" aarch64-linux-gnu "aarch64-linux-gnu-gcc -static" qemu-aarch64-static "" "$NO_NEST RUSTCLOAK_VM_NEST=1" 0; } \
             || echo "  SKIP arm64 (toolchain)";;
    win)   command -v x86_64-w64-mingw32-gcc >/dev/null && command -v wine >/dev/null \
             && { arch_one "win ALL-no-nest" x86_64-w64-windows-gnu "x86_64-w64-mingw32-gcc -static" wine .exe "$NO_NEST" 1
                  arch_one "win ALL+nest" x86_64-w64-windows-gnu "x86_64-w64-mingw32-gcc -static" wine .exe "$NO_NEST RUSTCLOAK_VM_NEST=1" 0; } \
             || echo "  SKIP win (toolchain)";;
  esac
done

echo
echo "== $((n-fails))/$n combos OK =="
[ $fails = 0 ] && echo "COMBOS PASS" || { echo "COMBOS FAILED ($fails)"; exit 1; }
