#!/usr/bin/env bash
# End-to-end Rust check via the opt-on-IR route. Two limitations, stated plainly:
#
#  * `rustc -Zllvm-plugins=<plugin>` does NOT load this plugin: rustc's bundled LLVM does not export
#    the `IRBuilderDefaultInserter` vtable the plugin references (it loads fine in opt/clang, which
#    link the full libLLVM). So the direct in-rustc path is blocked; obfuscate the emitted IR with
#    `opt` instead. (Fixing in-rustc loading is a build/linker task -- future work.)
#  * Running the obfuscated Rust needs linking the object against the Rust runtime/std, which isn't
#    wired up here, so behaviour is covered by the C/C++ differential (difftest.sh). This verifies
#    the Rust path at IR + object + string-leak level: the passes run on real rustc IR, the IR
#    verifies, it codegens to an object, and the secret strings are encrypted.
set -uo pipefail
cd "$(dirname "$0")/.."
NIGHTLY=${NIGHTLY:-nightly-2024-06-15}
OPT=${OPT:-opt-18}; CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SECRETS='rust::secret|rust::endpoint'
SRC=test/corpus/rust_prog.rs

rustc "+$NIGHTLY" -V >/dev/null 2>&1 || { echo "SKIP: need rustc +$NIGHTLY"; exit 0; }
[ -f "$PLUGIN" ] || { echo "build the plugin first (cmake --build build)"; exit 1; }

rustc "+$NIGHTLY" -O "$SRC" -o /tmp/rust_base && echo "baseline runs: $(/tmp/rust_base)"
rustc "+$NIGHTLY" -O --emit=llvm-ir -o /tmp/rust.ll "$SRC"
before=$(grep -cE "$SECRETS" /tmp/rust.ll || true)

RUSTCLOAK_VM=1 RUSTCLOAK_CONSTENC=1 $OPT -load-pass-plugin=$PLUGIN \
  -passes='strenc,function(virt,constenc,subst,bogus,flatten)' /tmp/rust.ll -S -o /tmp/rust_obf.ll

ok=1
$OPT -passes=verify /tmp/rust_obf.ll >/dev/null 2>&1 && echo "obf IR verifies" || { echo "FAIL: IR invalid"; ok=0; }
$CLANG -c /tmp/rust_obf.ll -o /tmp/rust_obf.o 2>/dev/null && echo "codegen -> object OK" || { echo "FAIL: codegen"; ok=0; }
after=$(grep -cE "$SECRETS" /tmp/rust_obf.ll || true)
oleak=$(strings /tmp/rust_obf.o 2>/dev/null | grep -cE "$SECRETS" || true)
echo "secret strings: IR before=$before after=$after ; object leak=$oleak"

{ [ "$ok" = 1 ] && [ "$before" -gt 0 ] && [ "$after" = 0 ] && [ "$oleak" = 0 ]; } \
  && echo "RUST_E2E PASS (IR + object + no leak; behaviour via difftest.sh)" \
  || { echo "RUST_E2E FAIL"; exit 1; }
