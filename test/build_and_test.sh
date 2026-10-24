#!/usr/bin/env bash
# Build RustCloak and check all three transforms: flattening preserves behaviour, string
# encryption removes plaintext, and both survive -O2 via the late-ordering plugin hook.
set -euo pipefail
cd "$(dirname "$0")/.."

CLANG=${CLANG:-clang-18}
OPT=${OPT:-opt-18}
LLVM_DIR=$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$LLVM_DIR" >/dev/null
cmake --build build >/dev/null
PLUGIN=build/libRustCloak.so

echo "== baseline =="
$CLANG -O1 -fno-discard-value-names -emit-llvm -S test/demo.c -o build/demo.ll
$CLANG -O0 build/demo.ll -o build/demo_orig
ORIG=$(./build/demo_orig)
echo "  output: $ORIG"

echo "== flatten (IR) =="
$OPT -load-pass-plugin=$PLUGIN -passes=flatten build/demo.ll -S -o build/demo_flat.ll
$OPT -passes=verify build/demo_flat.ll >/dev/null && echo "  IR verifies"
$CLANG -O0 build/demo_flat.ll -o build/demo_flat
FLAT=$(./build/demo_flat)
markers=$(grep -cE "cloak\.(dispatch|state|next|cur)" build/demo_flat.ll || true)

echo "== strenc (IR) =="
$OPT -load-pass-plugin=$PLUGIN -passes=strenc build/demo.ll -S -o build/demo_enc.ll
$CLANG -O0 build/demo_enc.ll -o build/demo_enc
ENC=$(./build/demo_enc)
enc_leak=$(strings build/demo_enc | grep -c "flatten-demo" || true)

echo "== full -O2 (-fpass-plugin, late ordering) =="
$CLANG -O2 -fpass-plugin=$PLUGIN test/demo.c -o build/demo_hard
HARD=$(./build/demo_hard)
o2_rungs=$(objdump -d -M intel build/demo_hard | awk '/<decode>:/,/^$/' | grep -cE "cmp.*0x[0-9a-f]{7,}" || true)
o2_leak=$(strings build/demo_hard | grep -c "flatten-demo" || true)

echo "== results =="
echo "  flatten: out=$FLAT markers=$markers"
echo "  strenc : out=$ENC plaintext_leak=$enc_leak"
echo "  -O2    : out=$HARD dispatcher_rungs=$o2_rungs plaintext_leak=$o2_leak"

ok=1
[ "$ORIG" = "$FLAT" ] && [ "$markers" -gt 0 ] || { echo "FAIL flatten"; ok=0; }
[ "$ORIG" = "$ENC" ]  && [ "$enc_leak" -eq 0 ] || { echo "FAIL strenc"; ok=0; }
[ "$ORIG" = "$HARD" ] && [ "$o2_rungs" -ge 3 ] && [ "$o2_leak" -eq 0 ] || { echo "FAIL -O2"; ok=0; }
[ "$ok" = 1 ] && echo "PASS: flatten + strenc + -O2 survival" || { echo "FAILED"; exit 1; }
