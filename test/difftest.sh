#!/usr/bin/env bash
# One-command differential battery for RustCloak. For a FIXED RUSTCLOAK_SEED, compile each program
# twice -- baseline (no plugin) and fully obfuscated (RUSTCLOAK_VM=1 + -O2 -fpass-plugin: virt,
# subst, bogus, flatten, strenc) -- run with identical inputs, and require identical exit code and
# stdout. Then run the coverage-guided `virt` differential fuzzer. Any mismatch is a miscompile.
# This is the gate the constant-pool bugs (uninitialised trunc mask, wrong GEP offset) now fail if
# reintroduced -- they both surface here as a stdout mismatch or a crash within seconds.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; CLANGXX=${CLANGXX:-clang++-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$(${LLVM_CONFIG:-llvm-config-18} --cmakedir)" >/dev/null
cmake --build build >/dev/null

fails=0; n=0
prog_check() { # name compiler src "args1|args2|..."
  local name=$1 cc=$2 src=$3 argset=$4
  n=$((n+1))
  $cc -O2 "$src" -o /tmp/dt_base 2>/dev/null \
    || { echo "  FAIL $name: baseline build"; fails=$((fails+1)); return; }
  RUSTCLOAK_VM=1 $cc -O2 -fpass-plugin=$PLUGIN "$src" -o /tmp/dt_obf 2>/dev/null \
    || { echo "  FAIL $name: obfuscated build"; fails=$((fails+1)); return; }
  local IFS='|'; local bad=0
  for args in $argset; do
    local bo bx oo ox
    bo=$(/tmp/dt_base $args); bx=$?
    oo=$(/tmp/dt_obf  $args); ox=$?
    [ "$bo" = "$oo" ] && [ "$bx" = "$ox" ] \
      || { echo "  FAIL $name [args='$args']: base(rc=$bx)='$bo' != obf(rc=$ox)='$oo'"; bad=1; }
  done
  [ $bad = 0 ] && echo "  OK   $name" || fails=$((fails+1))
}

echo "== program differential (fixed seed=$RUSTCLOAK_SEED) =="
prog_check demo        "$CLANG"   test/demo.c                 ""
prog_check vm_demo     "$CLANG"   test/vm_demo.c              "|stress"
prog_check c_loops     "$CLANG"   test/corpus/c_loops.c       ""
prog_check cpp_classes "$CLANGXX" test/corpus/cpp_classes.cpp ""
prog_check strdata     "$CLANG"   test/corpus/strdata.c       ""

# strenc must have encrypted the wide (i16) + table (i32) + i8 arrays in strdata; the plaintext
# marker must not survive in the obfuscated binary (/tmp/dt_obf is strdata's, built last above).
if strings /tmp/dt_obf 2>/dev/null | grep -q "strdata::secret::marker"; then
  echo "  FAIL strenc: plaintext marker leaked in obfuscated binary"; fails=$((fails+1))
else
  echo "  OK   strenc leak: no plaintext marker in obfuscated binary"
fi

prog_check floats      "$CLANG"   test/corpus/floats.c        ""

echo "== virt differential fuzz (short) =="
SECS=${SECS:-30} PLUGIN="$(pwd)/$PLUGIN" bash test/fuzz/difffuzz_vm.sh 2>&1 | sed 's/^/  /'

echo "== $((n-fails))/$n program checks OK =="
[ $fails = 0 ] && echo "DIFFTEST PASS" || { echo "DIFFTEST FAILED ($fails)"; exit 1; }
