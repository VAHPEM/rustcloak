#!/usr/bin/env bash
# Import/API hiding (RUSTCLOAK_HIDE_IMPORTS). getenv is resolved via dlsym at startup and every direct
# call rewritten, so it no longer appears in the import relocations or in `strings`, yet behaviour is
# unchanged. aarch64 ELF. (No RUSTCLOAK_VM, so the call stays a direct CallInst to rewrite.)
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=test/corpus/imp_prog.c
cmake -S . -B build -G Ninja -DLLVM_DIR="$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)" >/dev/null
cmake --build build >/dev/null
fail=0
base=$($CLANG -O2 "$SRC" -o /tmp/ih_base 2>/dev/null && /tmp/ih_base); bx=$?
RUSTCLOAK_HIDE_IMPORTS=getenv $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o /tmp/ih_obf -ldl 2>/dev/null \
  || { echo "  FAIL obf build"; exit 1; }
obf=$(/tmp/ih_obf 2>/dev/null); ox=$?
if [ "$obf" = "$base" ] && [ "$ox" = "$bx" ]; then echo "  OK   behaviour == baseline ($obf)"
else echo "  FAIL obf('$obf' rc=$ox) != baseline('$base' rc=$bx)"; fail=1; fi
readelf -r /tmp/ih_base 2>/dev/null | grep -q getenv && echo "  info baseline imports getenv (expected)"
if readelf -r /tmp/ih_obf 2>/dev/null | grep -q getenv; then echo "  FAIL getenv still in import relocations"; fail=1
else echo "  OK   getenv removed from import relocations"; fi
if readelf -r /tmp/ih_obf 2>/dev/null | grep -qi dlsym || readelf --dyn-syms /tmp/ih_obf 2>/dev/null | grep -qi dlsym; then
  echo "  OK   resolved through dlsym"; else echo "  WARN dlsym not visible in relocations"; fi
if strings /tmp/ih_obf 2>/dev/null | grep -qx getenv; then echo "  WARN plaintext 'getenv' string present"
else echo "  OK   no plaintext 'getenv' string"; fi
[ $fail = 0 ] && echo "IMPHIDE PASS" || { echo "IMPHIDE FAILED"; exit 1; }
