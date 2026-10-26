#!/usr/bin/env bash
# RUSTCLOAK_STRENC_SELFKEY: the string-decryption key marker is COMPUTED at run time by hashing the
# ciphertext (FNV-1a-32), not stored as a constant. This test shows:
#   1. behaviour preserved and no plaintext at rest (the strings still decrypt correctly),
#   2. the marker constructor actually hashes (FNV prime present) and stores NO literal magic -- so a
#      static tool cannot read the key; it must execute the hash over the real ciphertext,
#   3. contrast with RUSTCLOAK_ANTIEMU, whose marker ctor DOES store a constant magic.
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
RUSTCLOAK_STRENC_SELFKEY=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o "$WORK/sk" 2>/dev/null; GOT=$("$WORK/sk")
echo "== behaviour =="
[ "$GOLD" = "$GOT" ] && echo "  OK   output matches baseline ('$GOT')" || { echo "  FAIL '$GOT' != '$GOLD'"; fails=$((fails+1)); }

echo "== no plaintext at rest =="
RUSTCLOAK_STRENC_SELFKEY=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -c -o "$WORK/sk.o" 2>/dev/null
leak=$(strings "$WORK/sk.o" | grep -c "flatten-demo" || true)
[ "$leak" = 0 ] && echo "  OK   no plaintext leaked" || { echo "  FAIL plaintext leaked ($leak)"; fails=$((fails+1)); }

echo "== marker is computed, not a stored constant =="
$CLANG -O1 -emit-llvm -S "$SRC" -o "$WORK/ir.ll" 2>/dev/null
RUSTCLOAK_STRENC_SELFKEY=1 $OPT -load-pass-plugin=$PLUGIN -passes=strenc "$WORK/ir.ll" -S 2>/dev/null > "$WORK/sk.ll"
RUSTCLOAK_ANTIEMU=1       $OPT -load-pass-plugin=$PLUGIN -passes=strenc "$WORK/ir.ll" -S 2>/dev/null > "$WORK/ae.ll"
sk_hash=$(grep -c '16777619' "$WORK/sk.ll")
# a literal constant store to i32 other than the init 0: antiemu stores `store volatile i32 <magic>`
ae_const=$(grep -oE 'store volatile i32 -?[0-9]+,' "$WORK/ae.ll" | grep -vcE 'i32 0,' || true)
sk_const=$(grep -oE 'store volatile i32 -?[0-9]+,' "$WORK/sk.ll" | grep -vcE 'i32 0,' || true)
echo "  selfkey: FNV-hash present=$sk_hash  literal-magic-store=$sk_const"
echo "  antiemu: literal-magic-store=$ae_const (for contrast)"
[ "$sk_hash" -ge 1 ] && [ "$sk_const" = 0 ] && [ "$ae_const" -ge 1 ] \
  && echo "  OK   selfkey computes the key (no literal); antiemu stores one" \
  || { echo "  FAIL marker-derivation signal wrong"; fails=$((fails+1)); }

echo
[ $fails = 0 ] && echo "SELFKEY PASS" || { echo "SELFKEY FAILED ($fails)"; exit 1; }
