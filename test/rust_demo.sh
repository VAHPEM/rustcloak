#!/usr/bin/env bash
# Build a real Rust program with RustCloak via rustc's -Zllvm-plugins (needs a nightly whose LLVM
# matches the one the plugin was built against). Obfuscation runs at OptimizerLast, then rustc
# links a normal binary. Verifies: correct output, no plaintext secret, control flow flattened.
set -euo pipefail
cd "$(dirname "$0")/.."
PLUGIN="$PWD/build/libRustCloak.so"
TOOLCHAIN="${RUSTCLOAK_NIGHTLY:-nightly-2024-06-15}"   # LLVM 18.1.x, matches llvm-18-dev

[ -f "$PLUGIN" ] || { echo "build the plugin first (cmake --build build)"; exit 1; }

echo "== baseline =="
rustc "+$TOOLCHAIN" -O -o build/demo_rs_orig test/demo.rs
ORIG=$(./build/demo_rs_orig); echo "  $ORIG"

echo "== obfuscated (rustc -Zllvm-plugins) =="
rustc "+$TOOLCHAIN" -O -Zllvm-plugins="$PLUGIN" -o build/demo_rs_hard test/demo.rs
HARD=$(./build/demo_rs_hard); echo "  $HARD"

leak=$(strings build/demo_rs_hard | grep -c "7f3c-endpoint" || true)
flat=$(objdump -d -M intel build/demo_rs_hard 2>/dev/null | grep -cE "cmp.*0x[0-9a-f]{7,}" || true)
echo "  plaintext_leak=$leak  dispatcher_rungs=$flat"
[ "$ORIG" = "$HARD" ] && [ "$leak" -eq 0 ] && [ "$flat" -ge 3 ] \
  && echo "PASS: Rust binary obfuscated (strings encrypted, control flow flattened), still correct" \
  || { echo "FAIL"; exit 1; }
