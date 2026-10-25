#!/usr/bin/env bash
# Build a real Rust program with RustCloak via rustc's -Zllvm-plugins (needs a nightly whose LLVM
# matches the one the plugin was built against). Obfuscation runs at OptimizerLast, then rustc
# links a normal binary. Verifies: correct output, no plaintext secret, control flow flattened.
#
# Architecture-agnostic: it runs on whatever arch rustc targets (x86-64 or AArch64). "Flattened"
# is proven by the jump in the number of distinct large (>=0x1000) immediates in decode() -- the
# dispatcher gives every block a random 32-bit state constant -- rather than by an arch-specific
# disassembly pattern (x86-64 lowers the dispatcher to a `sub imm; je` ladder, AArch64 to a
# `cmp; b.eq` tree, so no single opcode pattern fits both).
set -euo pipefail
cd "$(dirname "$0")/.."
PLUGIN="$PWD/build/libRustCloak.so"
TOOLCHAIN="${RUSTCLOAK_NIGHTLY:-nightly-2024-06-15}"   # LLVM 18.1.x, matches llvm-18-dev
OBJDUMP=$(command -v llvm-objdump-18 || command -v llvm-objdump || command -v objdump)

[ -f "$PLUGIN" ] || { echo "build the plugin first (cmake --build build)"; exit 1; }

ARCH=$(rustc "+$TOOLCHAIN" -vV 2>/dev/null | awk '/^host:/{print $2}'); echo "arch: ${ARCH:-unknown}"

decode_consts() {  # distinct >=0x1000 immediates in the (mangled) decode function: the dispatcher
  "$OBJDUMP" -d --no-show-raw-insn "$1" 2>/dev/null \
    | awk '/[dD]ecode[0-9a-zA-Z_]*>:/{f=1;next} /^[0-9a-f]+ </{f=0}
           f{ while(match($0,/0x[0-9a-f]+/)){v=substr($0,RSTART+2,RLENGTH-2);
                if(length(v)>=4) c[v]=1; $0=substr($0,RSTART+RLENGTH)} }
           END{print length(c)+0}'
}

echo "== baseline =="
rustc "+$TOOLCHAIN" -O -o build/demo_rs_orig test/demo.rs
ORIG=$(./build/demo_rs_orig); echo "  $ORIG"
base_consts=$(decode_consts build/demo_rs_orig)

echo "== obfuscated (rustc -Zllvm-plugins) =="
rustc "+$TOOLCHAIN" -O -Zllvm-plugins="$PLUGIN" -o build/demo_rs_hard test/demo.rs
HARD=$(./build/demo_rs_hard); echo "  $HARD"
hard_consts=$(decode_consts build/demo_rs_hard)

leak=$(strings build/demo_rs_hard | grep -c "7f3c-endpoint" || true)
echo "  plaintext_leak=$leak  decode distinct-state-consts: baseline=$base_consts obfuscated=$hard_consts"

ok=1
[ "$ORIG" = "$HARD" ] || { echo "FAIL: behaviour changed"; ok=0; }
[ "$leak" -eq 0 ]     || { echo "FAIL: plaintext secret present"; ok=0; }
# flattening gives every block a random 32-bit state constant; require a clear jump (robust on
# both arches: x86-64 showed +46, C-demo aarch64 +67, so +20 is a safe floor)
[ "$hard_consts" -ge $(( base_consts + 20 )) ] || { echo "FAIL: no flattening (state consts not added)"; ok=0; }
[ "$ok" = 1 ] \
  && echo "PASS: Rust binary obfuscated (strings encrypted, control flow flattened), still correct ($ARCH)" \
  || { echo "FAIL"; exit 1; }
