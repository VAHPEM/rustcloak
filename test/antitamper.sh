#!/usr/bin/env bash
# Anti-tamper gate (RUSTCLOAK_ANTITAMPER). Build a PIE binary with the integrity pass, patch it with
# the post-link tool, and require: patched binary == baseline; a one-byte flip of the protected
# section is detected (output or exit code changes). aarch64 ELF.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=test/corpus/at_prog.c
echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)" >/dev/null
cmake --build build >/dev/null
fail=0
base=$($CLANG -O2 "$SRC" -o /tmp/at_base 2>/dev/null && /tmp/at_base); bx=$?
RUSTCLOAK_ANTITAMPER=1 $CLANG -O2 -fPIE -pie -fpass-plugin=$PLUGIN "$SRC" -o /tmp/at_obf 2>/dev/null \
  || { echo "  FAIL obfuscated build"; exit 1; }
pre=$(timeout 5 /tmp/at_obf 2>/dev/null)
echo "  info unpatched output='$pre' (expected to differ from baseline '$base')"
python3 tools/antitamper_patch.py /tmp/at_obf >/dev/null || { echo "  FAIL patch"; exit 1; }
post=$(timeout 5 /tmp/at_obf 2>/dev/null); px=$?
if [ "$post" = "$base" ] && [ "$px" = "$bx" ]; then echo "  OK   patched == baseline ($post)"
else echo "  FAIL patched('$post' rc=$px) != baseline('$base' rc=$bx)"; fail=1; fi
cp /tmp/at_obf /tmp/at_tam
python3 tools/antitamper_patch.py --flip-last /tmp/at_tam >/dev/null || { echo "  FAIL flip"; exit 1; }
tam=$(timeout 5 /tmp/at_tam 2>/dev/null); tx=$?
if [ "$tam" != "$base" ] || [ "$tx" != "$bx" ]; then echo "  OK   tamper detected (out='$tam' rc=$tx vs baseline '$base')"
else echo "  FAIL tamper NOT detected (out='$tam')"; fail=1; fi
[ $fail = 0 ] && echo "ANTITAMPER PASS" || { echo "ANTITAMPER FAILED"; exit 1; }
