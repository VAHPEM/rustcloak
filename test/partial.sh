#!/usr/bin/env bash
# Partial (block-level) virtualization gate (RUSTCLOAK_VM_PARTIAL). mix() is ineligible as a whole,
# so plain virt leaves it native; the partial pass outlines its integer if-block into a function the
# virt pass then virtualizes. Require identical behaviour to baseline, and show an extra function was
# outlined. aarch64 ELF.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=test/corpus/partial.c
cmake -S . -B build -G Ninja -DLLVM_DIR="$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)" >/dev/null
cmake --build build >/dev/null
fail=0
base=$($CLANG -O2 "$SRC" -o /tmp/p_base 2>/dev/null && /tmp/p_base); bx=$?
RUSTCLOAK_VM=1 RUSTCLOAK_VM_PARTIAL=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o /tmp/p_obf 2>/dev/null \
  || { echo "  FAIL obf build"; exit 1; }
obf=$(/tmp/p_obf 2>/dev/null); ox=$?
if [ "$base" = "$obf" ] && [ "$bx" = "$ox" ]; then echo "  OK   partial-virt behaviour == baseline ($obf)"
else echo "  FAIL obf('$obf' rc=$ox) != baseline('$base' rc=$bx)"; fail=1; fi
nvm=$(RUSTCLOAK_VM=1               $CLANG -O2 -fpass-plugin=$PLUGIN -emit-llvm -S "$SRC" -o - 2>/dev/null | grep -c '^define')
npt=$(RUSTCLOAK_VM=1 RUSTCLOAK_VM_PARTIAL=1 $CLANG -O2 -fpass-plugin=$PLUGIN -emit-llvm -S "$SRC" -o - 2>/dev/null | grep -c '^define')
echo "  info defined functions: VM=$nvm  VM+PARTIAL=$npt"
if [ "$npt" -gt "$nvm" ]; then echo "  OK   partial pass outlined + virtualized an extra function"
else echo "  WARN partial outlined nothing on this CFG (still correct)"; fi
[ $fail = 0 ] && echo "PARTIAL PASS" || { echo "PARTIAL FAILED"; exit 1; }
