#!/usr/bin/env bash
# RUSTCLOAK_STRENC_SYSCALLKEY: the string-decryption key is gated on a real syscall (time(NULL)!=0).
# On a real host this is always true, so behaviour is preserved and strings decrypt correctly; an
# isolated emulator that stubs the syscall to 0 would recover garbage. Linux-first. Checks:
#   1. behaviour preserved + no plaintext at rest,
#   2. the marker ctor actually CALLS time (the gate is present, not a stored constant alone).
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=${SRC:-test/demo.c}
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fails=0

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

$CLANG -O2 "$SRC" -o "$WORK/base" 2>/dev/null; GOLD=$("$WORK/base")
RUSTCLOAK_STRENC_SYSCALLKEY=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o "$WORK/sk" 2>/dev/null; GOT=$("$WORK/sk")
echo "== behaviour =="
[ "$GOLD" = "$GOT" ] && echo "  OK   output matches baseline ('$GOT')" || { echo "  FAIL '$GOT' != '$GOLD'"; fails=$((fails+1)); }

echo "== no plaintext at rest =="
RUSTCLOAK_STRENC_SYSCALLKEY=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -c -o "$WORK/sk.o" 2>/dev/null
leak=$(strings "$WORK/sk.o" | grep -c "flatten-demo" || true)
[ "$leak" = 0 ] && echo "  OK   no plaintext leaked" || { echo "  FAIL plaintext leaked ($leak)"; fails=$((fails+1)); }

echo "== key is gated on the time() syscall =="
$CLANG -O1 -emit-llvm -S "$SRC" -o "$WORK/ir.ll" 2>/dev/null
RUSTCLOAK_STRENC_SYSCALLKEY=1 $OPT -load-pass-plugin=$PLUGIN -passes=strenc "$WORK/ir.ll" -S 2>/dev/null > "$WORK/sk.ll"
calls_time=$(grep -cE 'call .*@time\b' "$WORK/sk.ll" || true)
echo "  time() calls in marker ctor: $calls_time"
[ "$calls_time" -ge 1 ] && echo "  OK   decryption key gated on a runtime syscall" \
  || { echo "  FAIL no time() gate emitted"; fails=$((fails+1)); }

echo
[ $fails = 0 ] && echo "SYSCALLKEY PASS" || { echo "SYSCALLKEY FAILED ($fails)"; exit 1; }
