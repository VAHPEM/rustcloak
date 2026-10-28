#!/usr/bin/env bash
# License key gate (RUSTCLOAK_LICENSE). Build with the expected key hash; the binary runs correctly
# only with the right RC_KEY, and corrupts (branch-free) with a wrong or missing key. aarch64 ELF.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=test/corpus/at_prog.c
cmake -S . -B build -G Ninja -DLLVM_DIR="$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)" >/dev/null
cmake --build build >/dev/null
KEY="VALIDKEY-2026"
HASH=$(python3 -c "
k=b'$KEY'; h=0xcbf29ce484222325
for b in k: h=((h^b)*0x100000001b3)&0xffffffffffffffff
print('0x%016x'%h)")
fail=0
base=$($CLANG -O2 "$SRC" -o /tmp/lic_base 2>/dev/null && /tmp/lic_base); bx=$?
RUSTCLOAK_LICENSE=$HASH $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o /tmp/lic_obf 2>/dev/null \
  || { echo "  FAIL obf build"; exit 1; }
good=$(RC_KEY="$KEY" timeout 5 /tmp/lic_obf 2>/dev/null); gx=$?
wrong=$(RC_KEY="NOPE" timeout 5 /tmp/lic_obf 2>/dev/null)
none=$(timeout 5 /tmp/lic_obf 2>/dev/null)
if [ "$good" = "$base" ] && [ "$gx" = "$bx" ]; then echo "  OK   valid key == baseline ($good)"
else echo "  FAIL valid('$good' rc=$gx) != baseline('$base' rc=$bx)"; fail=1; fi
if [ "$wrong" != "$base" ]; then echo "  OK   wrong key corrupts (out='$wrong')"; else echo "  FAIL wrong key not detected"; fail=1; fi
if [ "$none" != "$base" ]; then echo "  OK   missing key corrupts (out='$none')"; else echo "  FAIL missing key not detected"; fail=1; fi
[ $fail = 0 ] && echo "LICENSE PASS" || { echo "LICENSE FAILED"; exit 1; }
