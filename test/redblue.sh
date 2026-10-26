#!/usr/bin/env bash
# Red/blue measurement: run the BLUE side -- the rust-deobf analysis toolkit, RustCloak's
# counterpart -- against RustCloak's own VM output and report, with real numbers, exactly what it
# recovers. This closes the loop: instead of proxy metrics (entropy, fold-survival), it asks the
# actual deobfuscator how much it gets back.
#
# rust-deobf is a SEPARATE repo (https://github.com/VAHPEM/rust-deobf). Point RUSTDEOBF at a checkout
# (default: a sibling ../vahpem/rust-deobf), and have its Python deps installed
# (pip install 'lief>=0.16' 'capstone>=5.0,<6' 'unicorn>=2.1,<3' 'z3-solver>=4.12'). If either is
# missing the script prints how to get them and SKIPs -- it is a measurement hook, not a build gate.
#
# What it measures, on the single-function fixture test/vm_one.c (ground-truth constants 0x9e3779b9
# and 0x85ebca6b from keycheck):
#   detect_vm.py        -- does the static detector even flag the function as virtualized?
#   lift_vm.py          -- does the static lifter recover the bytecode/opcode map?
#   devirt_emulate.py   -- does the EMULATION devirtualizer reconstruct keycheck's expression?
# and repeats the emulation attempt against each hardening knob (JMP dispatch, integrity, nesting).
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN="$(pwd)/build/libRustCloak.so"
RUSTDEOBF=${RUSTDEOBF:-/home/user/vahpem/rust-deobf}
OBJDUMP=$(command -v llvm-objdump-18 || command -v llvm-objdump || command -v objdump)

if [ ! -d "$RUSTDEOBF" ] || [ ! -f "$RUSTDEOBF/premium/devirt_emulate.py" ]; then
  echo "SKIP: rust-deobf not found at RUSTDEOBF=$RUSTDEOBF"
  echo "  git clone https://github.com/VAHPEM/rust-deobf \"\$RUSTDEOBF\""
  exit 0
fi
if ! python3 -c 'import lief,capstone,unicorn' 2>/dev/null; then
  echo "SKIP: rust-deobf python deps missing"
  echo "  pip install 'lief>=0.16' 'capstone>=5.0,<6' 'unicorn>=2.1,<3' 'z3-solver>=4.12'"
  exit 0
fi

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

# build vm_one under a given set of RustCloak env flags; echo the binary path and keycheck's VA
build_one() { # envflags outpath
  env $1 RUSTCLOAK_VM=1 $CLANG -O2 -fpass-plugin="$PLUGIN" test/vm_one.c -o "$2" 2>/dev/null
  $OBJDUMP -t "$2" 2>/dev/null | grep -iE ' keycheck$' | awk '{print "0x"$1}'
}
# did the emulation devirtualizer reconstruct keycheck? (its two signature constants both appear)
recovered() { echo "$1" | grep -qiE '0x9e3779b9' && echo "$1" | grep -qiE '0x85ebca6b'; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo
echo "========================= STATIC blue tools vs RustCloak virt ========================="
va=$(build_one "" "$TMP/plain")
det=$(python3 "$RUSTDEOBF/scripts/detect_vm.py" "$TMP/plain" 2>&1)
echo "$det" | grep -qiE 'no virtualized' && echo "  detect_vm.py   : NOT detected (static VM detector defeated)" \
                                         || echo "  detect_vm.py   : detected -> $(echo "$det"|tail -1)"
lift=$(timeout 120 python3 "$RUSTDEOBF/premium/lift_vm.py" "$TMP/plain" 2>&1)
echo "$lift" | grep -qiE 'no virtualized|could be lifted' && echo "  lift_vm.py     : NOT lifted (static lifter defeated by randomized opcodes/operand keys)" \
                                                          || echo "  lift_vm.py     : lifted"

echo
echo "===================== EMULATION devirtualizer vs each hardening knob ====================="
printf "  %-22s %s\n" "RustCloak config" "devirt_emulate.py recovers keycheck?"
for spec in "plain:" "VM_JMP:RUSTCLOAK_VM_JMP=1" "integrity:RUSTCLOAK_VM_INTEGRITY=1" "nested:RUSTCLOAK_VM_NEST=1" "jmp+nest+integ:RUSTCLOAK_VM_JMP=1 RUSTCLOAK_VM_NEST=1 RUSTCLOAK_VM_INTEGRITY=1"; do
  name=${spec%%:*}; flags=${spec#*:}
  va=$(build_one "$flags" "$TMP/b")
  out=$(timeout 240 python3 "$RUSTDEOBF/premium/devirt_emulate.py" "$TMP/b" "$va" 2>&1)
  if recovered "$out"; then printf "  %-22s %s\n" "$name" "YES (full expression)"
  else printf "  %-22s %s\n" "$name" "no -> $(echo "$out"|head -1)"; fi
done

echo
echo "== reading =="
echo "  Structural VM hardening (randomized opcodes, encrypted operands, jump-table dispatch,"
echo "  integrity, nesting) defeats rust-deobf's STATIC detector and lifter, but EMULATION observes"
echo "  the real computation and reconstructs it regardless of structure -- the known state of the"
echo "  art. The blue counter to emulation is running the code (the sample is never a RustCloak goal:"
echo "  RustCloak answers emulation only where it can do so statically, e.g. the strenc SELFKEY/"
echo "  ANTIEMU loader-bound keys, not with anti-analysis runtime behaviour)."
