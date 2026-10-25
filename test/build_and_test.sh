#!/usr/bin/env bash
# Build RustCloak and check all three transforms: flattening preserves behaviour, string
# encryption removes plaintext, and both survive -O2 via the late-ordering plugin hook.
#
# Architecture-agnostic. The obfuscation is an LLVM-IR transform, so it applies to any target;
# the correctness gates are checked at the IR level (which is arch-independent) rather than by
# disassembling, because the dispatcher's MACHINE code differs by arch (x86-64 lowers the switch
# to a `sub imm; je` ladder, AArch64 to a `cmp wREG; b.eq` compare-tree). Runs natively by
# default; set RUSTCLOAK_TARGET=<triple> (e.g. aarch64-linux-gnu) to cross-compile and verify the
# IR/object instead (behaviour is not run for a non-native target). The machine-code dispatcher
# line is informational and adapts to the arch.
set -euo pipefail
cd "$(dirname "$0")/.."

CLANG=${CLANG:-clang-18}
OPT=${OPT:-opt-18}
LLVM_DIR=$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)
OBJDUMP=$(command -v llvm-objdump-18 || command -v llvm-objdump || command -v objdump)

# Native arch (normalise arm64 -> aarch64), and whether the chosen target is native.
NATIVE=$(uname -m); [ "$NATIVE" = "arm64" ] && NATIVE=aarch64
TGT=""; RUN=1; ARCH="$NATIVE"
if [ -n "${RUSTCLOAK_TARGET:-}" ]; then
  TGT="-target ${RUSTCLOAK_TARGET}"
  case "$RUSTCLOAK_TARGET" in aarch64*|arm64*) ARCH=aarch64;; x86_64*|amd64*) ARCH=x86_64;; esac
  case "$RUSTCLOAK_TARGET" in *"$NATIVE"*) RUN=1;; *) RUN=0;; esac
fi
echo "target: ${RUSTCLOAK_TARGET:-native ($NATIVE)}   run-behaviour: $RUN"

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$LLVM_DIR" >/dev/null
cmake --build build >/dev/null
PLUGIN=build/libRustCloak.so

# Arch-independent flatten markers injected by the pass (kept only with value names preserved).
MARK='cloak\.(dispatch|state|next|cur)'
VN='-fno-discard-value-names'

echo "== baseline (IR + optional native run) =="
$CLANG -O1 $VN $TGT -emit-llvm -S test/demo.c -o build/demo.ll
ORIG=""
if [ "$RUN" = 1 ]; then $CLANG -O0 $TGT build/demo.ll -o build/demo_orig; ORIG=$(./build/demo_orig); echo "  output: $ORIG"; fi

echo "== flatten (IR) =="
$OPT -load-pass-plugin=$PLUGIN -passes=flatten build/demo.ll -S -o build/demo_flat.ll
$OPT -passes=verify build/demo_flat.ll >/dev/null && echo "  IR verifies"
markers=$(grep -cE "$MARK" build/demo_flat.ll || true)
FLAT="$ORIG"
if [ "$RUN" = 1 ]; then $CLANG -O0 $TGT build/demo_flat.ll -o build/demo_flat; FLAT=$(./build/demo_flat); fi

echo "== strenc (IR) =="
$OPT -load-pass-plugin=$PLUGIN -passes=strenc build/demo.ll -S -o build/demo_enc.ll
$CLANG -O0 $TGT build/demo_enc.ll -c -o build/demo_enc.o
enc_leak=$(strings build/demo_enc.o | grep -c "flatten-demo" || true)
ENC="$ORIG"
if [ "$RUN" = 1 ]; then $CLANG -O0 $TGT build/demo_enc.ll -o build/demo_enc; ENC=$(./build/demo_enc); fi

echo "== full -O2 (-fpass-plugin, late ordering) =="
$CLANG -O2 $VN $TGT -fpass-plugin=$PLUGIN -emit-llvm -S test/demo.c -o build/demo_hard.ll
o2_markers=$(grep -cE "$MARK" build/demo_hard.ll || true)        # obfuscation survived the optimizer
$CLANG -O2 $TGT -fpass-plugin=$PLUGIN -c test/demo.c -o build/demo_hard.o
o2_leak=$(strings build/demo_hard.o | grep -c "flatten-demo" || true)
o2_cmp=$($OBJDUMP -d --no-show-raw-insn build/demo_hard.o 2>/dev/null | sed -n '/<decode>:/,/^$/p' \
         | grep -cE "\b(cmp|sub)\b" || true)                     # informational: dispatcher size
HARD="$ORIG"
if [ "$RUN" = 1 ]; then $CLANG -O2 $TGT -fpass-plugin=$PLUGIN test/demo.c -o build/demo_hard; HARD=$(./build/demo_hard); fi

echo "== results (arch=$ARCH) =="
echo "  flatten: out='${FLAT}' markers=$markers"
echo "  strenc : out='${ENC}' plaintext_leak=$enc_leak"
echo "  -O2    : out='${HARD}' survived_markers=$o2_markers plaintext_leak=$o2_leak dispatcher_insns=$o2_cmp"

ok=1
[ "$markers" -gt 0 ] || { echo "FAIL flatten: no markers"; ok=0; }
[ "$enc_leak" -eq 0 ] || { echo "FAIL strenc: plaintext leaked"; ok=0; }
[ "$o2_markers" -gt 0 ] && [ "$o2_leak" -eq 0 ] || { echo "FAIL -O2: not survived / leaked"; ok=0; }
if [ "$RUN" = 1 ]; then
  [ "$ORIG" = "$FLAT" ] || { echo "FAIL flatten: behaviour changed"; ok=0; }
  [ "$ORIG" = "$ENC" ]  || { echo "FAIL strenc: behaviour changed"; ok=0; }
  [ "$ORIG" = "$HARD" ] || { echo "FAIL -O2: behaviour changed"; ok=0; }
else
  echo "  [cross-compile to $ARCH: IR/object verified, behaviour not run]"
fi
[ "$ok" = 1 ] && echo "PASS: flatten + strenc + -O2 survival ($ARCH)" || { echo "FAILED"; exit 1; }
