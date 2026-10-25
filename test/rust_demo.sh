#!/usr/bin/env bash
# Obfuscate a real Rust program with RustCloak, two ways, and verify it:
#
#   1. rustc -Zllvm-plugins (the convenient path): rustc loads the plugin and obfuscates at
#      OptimizerLast, then links a normal binary. This only works if rustc's *bundled* LLVM
#      exports the symbols the plugin needs -- rustup toolchains statically link LLVM and hide
#      most of them, so the plugin fails to load there (a property of the rustc build, not the
#      architecture). When it works, we run the binary and check output + no plaintext + flattening.
#
#   2. opt-on-IR (the portable path, used as a fallback): `rustc --emit=llvm-ir` then the system
#      `opt` (same LLVM the plugin was built against) runs the passes on the real rustc IR. This
#      works on any host and any arch; we verify on the transformed IR that the secret string is
#      gone (strenc) and the dispatcher markers are present (flatten).
#
# Architecture-agnostic throughout (x86-64 or AArch64).
set -euo pipefail
cd "$(dirname "$0")/.."
PLUGIN="$PWD/build/libRustCloak.so"
TOOLCHAIN="${RUSTCLOAK_NIGHTLY:-nightly-2024-06-15}"   # LLVM 18.1.x, matches llvm-18-dev
OPT=${OPT:-opt-18}
OBJDUMP=$(command -v llvm-objdump-18 || command -v llvm-objdump || command -v objdump)
SECRET="7f3c-endpoint"
MARK='cloak\.(dispatch|state|next|cur)'

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

echo "== obfuscated: trying rustc -Zllvm-plugins =="
if err=$(rustc "+$TOOLCHAIN" -O -Zllvm-plugins="$PLUGIN" -o build/demo_rs_hard test/demo.rs 2>&1); then
  HARD=$(./build/demo_rs_hard); echo "  $HARD"
  base_consts=$(decode_consts build/demo_rs_orig)
  hard_consts=$(decode_consts build/demo_rs_hard)
  leak=$(strings build/demo_rs_hard | grep -c "$SECRET" || true)
  echo "  plaintext_leak=$leak  decode distinct-state-consts: baseline=$base_consts obfuscated=$hard_consts"
  ok=1
  [ "$ORIG" = "$HARD" ] || { echo "FAIL: behaviour changed"; ok=0; }
  [ "$leak" -eq 0 ]     || { echo "FAIL: plaintext secret present"; ok=0; }
  [ "$hard_consts" -ge $(( base_consts + 20 )) ] || { echo "FAIL: no flattening (state consts not added)"; ok=0; }
  [ "$ok" = 1 ] \
    && echo "PASS (rustc -Zllvm-plugins): obfuscated Rust binary runs correctly, strings encrypted, flattened ($ARCH)" \
    || { echo "FAIL"; exit 1; }
else
  echo "  rustc could not load the plugin: ${err##*: }"
  echo "  -> this rustc's bundled LLVM hides plugin symbols; using the portable opt-on-IR path."
  echo "== obfuscated: opt-on-IR (portable) =="
  rustc "+$TOOLCHAIN" -O --emit=llvm-ir -o build/demo_rs.ll test/demo.rs
  $OPT -load-pass-plugin="$PLUGIN" -passes='strenc,function(subst,bogus,flatten)' \
       build/demo_rs.ll -S -o build/demo_rs_obf.ll
  base_secret=$(grep -c "$SECRET" build/demo_rs.ll || true)
  obf_secret=$(grep -c "$SECRET" build/demo_rs_obf.ll || true)
  markers=$(grep -cE "$MARK" build/demo_rs_obf.ll || true)
  echo "  secret in baseline IR=$base_secret  in obfuscated IR=$obf_secret  flatten markers=$markers"
  ok=1
  [ "$base_secret" -gt 0 ] || { echo "FAIL: secret not found in baseline IR (test setup)"; ok=0; }
  [ "$obf_secret" -eq 0 ]  || { echo "FAIL: secret still plaintext after strenc"; ok=0; }
  [ "$markers" -gt 0 ]     || { echo "FAIL: no flatten markers in obfuscated IR"; ok=0; }
  [ "$ok" = 1 ] \
    && echo "PASS (opt-on-IR): RustCloak transforms real rustc IR -- secret encrypted, control flow flattened ($ARCH)" \
    || { echo "FAIL"; exit 1; }
fi
