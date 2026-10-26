#!/usr/bin/env bash
# Strength/cost matrix for RustCloak. For a fixed RUSTCLOAK_SEED, measure each transform's COST
# (binary size, stress runtime) and its ANALYSIS-DIFFICULTY signal:
#   virt    -- interpreter handler count, opcode entropy, single-opcode share (frequency resistance)
#   bogus   -- opaque junk-blocks emitted vs surviving `opt -O2` (fold resistance)
#   subst   -- integer-arithmetic instruction count before/after (MBA expansion)
#   flatten -- dispatcher switch arms (one per original block)
#   strenc  -- plaintext secrets leaking to `strings` (should be 0)
# Transforms are measured in isolation via `opt -passes=<x>` on -O1 IR, then compiled to run; the
# full pipeline is the -O2 -fpass-plugin build. "measure before you conclude."
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=${SRC:-test/vm_demo.c}
HERE=test

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

$CLANG -O1 -fno-discard-value-names -emit-llvm -S "$SRC" -o /tmp/m.ll

# compile an .ll to a runnable binary; echo its size
build_ll(){ $CLANG -O2 "$1" -o /tmp/mbin 2>/dev/null && stat -c%s /tmp/mbin; }
# wall-time of N stress runs (seconds)
runtime(){ local s e; s=$(date +%s.%N); for i in $(seq 1 "${1:-10}"); do /tmp/mbin stress >/dev/null; done; e=$(date +%s.%N); awk "BEGIN{printf \"%.2f\", $e-$s}"; }

pass_ll(){ # name env passes-or-VM -> writes /tmp/t.ll
  local env="$1" p="$2"
  if [ "$p" = "VM" ]; then env $env RUSTCLOAK_VM=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' /tmp/m.ll -S -o /tmp/t.ll 2>/dev/null
  else env $env $OPT -load-pass-plugin=$PLUGIN -passes="$p" /tmp/m.ll -S -o /tmp/t.ll 2>/dev/null; fi
}

echo
echo "========================= COST (size bytes / 10x stress seconds) ========================="
printf "%-28s %12s %12s\n" "config" "size" "runtime"
# baseline
sz=$(build_ll /tmp/m.ll); rt=$(runtime); printf "%-28s %12s %12s\n" "baseline (-O1 IR)" "$sz" "$rt"
for spec in "subst:subst" "bogus:bogus" "flatten:flatten" "strenc:strenc"; do
  name=${spec%%:*}; p="function(${spec##*:})"; [ "$name" = strenc ] && p="strenc"
  pass_ll "" "$p"; sz=$(build_ll /tmp/t.ll); rt=$(runtime); printf "%-28s %12s %12s\n" "$name only" "$sz" "$rt"
done
pass_ll "" VM; sz=$(build_ll /tmp/t.ll); rt=$(runtime); printf "%-28s %12s %12s\n" "virt only" "$sz" "$rt"
env RUSTCLOAK_VM=1 $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -o /tmp/mbin 2>/dev/null
sz=$(stat -c%s /tmp/mbin); rt=$(runtime); printf "%-28s %12s %12s\n" "full (-O2 all + VM)" "$sz" "$rt"

echo
echo "========================= DIFFICULTY ========================="
# virt: opcode entropy / handlers
pass_ll "" VM
echo -n "virt   : "; python3 "$HERE/opcode_entropy.py" /tmp/t.ll
# bogus: opaque-predicate CFG clutter and its survival of a simplifycfg pass (the junk arm now
# feeds the dataflow through a PHI instead of a volatile store-to-sink, so the signal is branches).
pass_ll "" "function(bogus)"
b1=$(grep -c 'br i1' /tmp/t.ll || true)
$OPT -passes=simplifycfg /tmp/t.ll -S -o /tmp/t2.ll 2>/dev/null
b2=$(grep -c 'br i1' /tmp/t2.ll || true)
sink=$(grep -c 'store volatile' /tmp/t.ll || true)
echo "bogus  : conditional branches=$b1  surviving simplifycfg=$b2  volatile-store-to-sink=$sink (0 = no signature)"
# subst: MBA expansion
before=$(grep -cE '= (add|sub|mul|and|or|xor) i(8|16|32|64)' /tmp/m.ll || true)
pass_ll "" "function(subst)"
after=$(grep -cE '= (add|sub|mul|and|or|xor) i(8|16|32|64)' /tmp/t.ll || true)
echo "subst  : integer-arith instructions before=$before  after=$after  (expansion x$(awk "BEGIN{printf \"%.2f\", $after/$before}"))"
# flatten: dispatcher arms
pass_ll "" "function(flatten)"
arms=$(grep -oE 'i32 -?[0-9]+, label %' /tmp/t.ll | wc -l)
echo "flatten: dispatcher switch arms (hidden block transitions)=$arms"
# strenc: plaintext leak
env $CLANG -O2 -fpass-plugin=$PLUGIN "$SRC" -c -o /tmp/mo.o 2>/dev/null
leak=$(strings /tmp/mo.o | grep -cE 'mix=|check=|stress=|fold64=' || true)
echo "strenc : plaintext format-string leak in object=$leak (0 = no plaintext at rest)"
echo
echo "done."
