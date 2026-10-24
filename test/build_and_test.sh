#!/usr/bin/env bash
# Build RustCloak, flatten the demo, and check the flattened binary behaves identically.
set -euo pipefail
cd "$(dirname "$0")/.."

CLANG=${CLANG:-clang-18}
OPT=${OPT:-opt-18}
LLVM_DIR=$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$LLVM_DIR" >/dev/null
cmake --build build >/dev/null
PLUGIN=build/libRustCloak.so

echo "== compile baseline =="
$CLANG -O1 -fno-discard-value-names -emit-llvm -S test/demo.c -o build/demo.ll
$CLANG -O0 build/demo.ll -o build/demo_orig
ORIG=$(./build/demo_orig)

echo "== flatten =="
$OPT -load-pass-plugin=$PLUGIN -passes=flatten build/demo.ll -S -o build/demo_flat.ll
$OPT -passes=verify build/demo_flat.ll >/dev/null && echo "  IR verifies"
$CLANG -O0 build/demo_flat.ll -o build/demo_flat
FLAT=$(./build/demo_flat)

echo "== result =="
echo "  original : $ORIG"
echo "  flattened: $FLAT"
markers=$(grep -cE "cloak\.(dispatch|state|next|cur)" build/demo_flat.ll || true)
echo "  flatten markers in IR: $markers"
[ "$ORIG" = "$FLAT" ] && [ "$markers" -gt 0 ] && echo "PASS: behaviour preserved and control flow flattened" || { echo "FAIL"; exit 1; }
