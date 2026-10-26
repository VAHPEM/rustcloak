#!/usr/bin/env bash
# Regression gate for the virt PHI-edge miscompile (see test/vm_phi.ll): a PHI in a single-
# predecessor block reached by a conditional branch must still get its copy. Runs the fixture through
# virt in several configurations and requires the result to match the un-virtualized baseline.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fails=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

$CLANG -O0 test/vm_phi.ll -o "$WORK/base" 2>/dev/null; "$WORK/base"; BASE=$?
echo "  baseline rc=$BASE"
for cfg in "" "RUSTCLOAK_VM_JMP=1" "RUSTCLOAK_VM_NEST=1" "RUSTCLOAK_VM_INTEGRITY=1" \
           "RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_INTEGRITY=1"; do
  env $cfg RUSTCLOAK_VM=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' test/vm_phi.ll -S 2>/dev/null \
    | $CLANG -O0 -x ir - -o "$WORK/v" 2>/dev/null || { echo "  FAIL [${cfg:-plain}]: build"; fails=$((fails+1)); continue; }
  "$WORK/v"; rc=$?
  [ "$rc" = "$BASE" ] && echo "  OK   [${cfg:-plain}] rc=$rc" || { echo "  FAIL [${cfg:-plain}]: rc=$rc != $BASE"; fails=$((fails+1)); }
done

echo
[ $fails = 0 ] && echo "PHI_REGRESS PASS" || { echo "PHI_REGRESS FAILED ($fails)"; exit 1; }
