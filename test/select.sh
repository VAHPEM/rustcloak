#!/usr/bin/env bash
# Selective-virtualization test. On test/vm_select.c (five eligible functions: two sensitive-named,
# two ordinary, one ordinary-named but annotate("rustcloak_vm")), confirm each selection mode
# virtualizes exactly the intended set, and that behaviour is preserved whatever the selection.
#
# How many functions were virtualized is read as the number of `switch i8` dispatchers in the
# virt-only IR -- the VM emits exactly one per virtualized function, and no ordinary code has an i8
# switch. The annotated function must be virtualized in EVERY mode (even RATIO=0), the denylist must
# win in every mode, and the sensitive-name heuristic must pick the licence/crypto routines.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

$CLANG -O1 -fno-discard-value-names -emit-llvm -S test/vm_select.c -o "$WORK/sel.ll" 2>/dev/null
count() { env "$@" RUSTCLOAK_VM=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' \
            "$WORK/sel.ll" -S 2>/dev/null | grep -c "switch i8 "; }

fails=0
expect() { # label expected env...
  local label=$1 exp=$2; shift 2
  local got; got=$(count "$@")
  if [ "$got" = "$exp" ]; then echo "  OK   $label: virtualized=$got"
  else echo "  FAIL $label: virtualized=$got expected=$exp"; fails=$((fails+1)); fi
}

echo "== selection counts (of 5 eligible functions) =="
expect "default (all)"        5
expect "SELECTIVE (sensitive+annotated)" 3 RUSTCLOAK_VM_SELECTIVE=1
expect "ONLY=license_check"   2 RUSTCLOAK_VM_ONLY=license_check
expect "ONLY=crypt,add_helper" 3 RUSTCLOAK_VM_ONLY=crypt,add_helper
expect "SKIP=crypt"           4 RUSTCLOAK_VM_SKIP=crypt
expect "RATIO=0 (annotated only)" 1 RUSTCLOAK_VM_RATIO=0
expect "SELECTIVE + SKIP=licen" 2 RUSTCLOAK_VM_SELECTIVE=1 RUSTCLOAK_VM_SKIP=licen

echo "== behaviour preserved under selection =="
$CLANG -O2 test/vm_select.c -o "$WORK/base" 2>/dev/null
for a in 1234567 7 4242; do golden=$("$WORK/base" $a)
  for mode in "" "RUSTCLOAK_VM_SELECTIVE=1" "RUSTCLOAK_VM_ONLY=crypt" "RUSTCLOAK_VM_RATIO=50"; do
    env $mode RUSTCLOAK_VM=1 $CLANG -O2 -fpass-plugin=$PLUGIN test/vm_select.c -o "$WORK/o" 2>/dev/null
    got=$("$WORK/o" $a)
    [ "$got" = "$golden" ] || { echo "  FAIL [${mode:-default} arg=$a]: $got != $golden"; fails=$((fails+1)); }
  done
done
[ $fails = 0 ] && echo "  OK   all modes match baseline on all inputs"

echo
[ $fails = 0 ] && echo "SELECT PASS" || { echo "SELECT FAILED ($fails)"; exit 1; }
