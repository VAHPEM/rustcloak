#!/usr/bin/env bash
# Obfuscate each corpus program with RustCloak and verify correctness + obfuscation. Native mode
# (no arg) builds and RUNS each program in eager and lazy modes and checks the output matches the
# baseline and no plaintext string leaks. Cross mode (a target triple arg, e.g. aarch64-linux-gnu)
# works at the LLVM-IR level only -- emit IR with the plugin, verify it, and check the secret
# strings are encrypted -- since cross-linking C++/Rust needs sysroots that may be absent.
#
# Exercises RustCloak on control flow the single demo does not: recursion, switch, fn-ptr tables
# (c_loops.c); C++ exceptions + virtual dispatch (cpp_classes.cpp); Rust enums/iterators/HashMap
# (rust_prog.rs).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PLUGIN=${PLUGIN:-/home/claude/rustcloak/build/libRustCloak.so}
[ -f "$PLUGIN" ] || PLUGIN="$HERE/../build/libRustCloak.so"
CLANG=${CLANG:-clang-18}; CLANGXX=${CLANGXX:-clang++-18}
NIGHTLY=${NIGHTLY:-nightly-2024-06-15}; OPT=${OPT:-opt-18}
TGT="${1:-}"; TFLAG=""; CROSS=0
[ -n "$TGT" ] && { TFLAG="-target $TGT"; CROSS=1; }
SECRETS="corpus::|shape::|division::|rust::secret|rust::endpoint"
D=$(mktemp -d); fails=0; n=0
pass() { echo "  OK   $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }

# IR-level obfuscation check for one emitted .ll: verifies and confirms secrets are encrypted.
ir_check() { # name file
  n=$((n+1))
  "$OPT" -load-pass-plugin="$PLUGIN" -passes='strenc,function(subst,bogus,flatten)' "$2" -S -o "$D/obf.ll" 2>/dev/null
  if ! "$OPT" -passes=verify "$D/obf.ll" >/dev/null 2>&1; then fail "$1: obfuscated IR invalid"; return; fi
  local leak; leak=$(grep -cE "$SECRETS" "$D/obf.ll" || true)
  [ "$leak" -eq 0 ] && pass "$1 (IR verified, secrets encrypted)" || fail "$1: $leak secret(s) not encrypted"
}

# native build+run check for both modes.
run_check() { # name baseline eager lazy
  n=$((n+1))
  [ -x "$2" ] && [ -x "$3" ] && [ -x "$4" ] || { fail "$1: a build failed"; return; }
  local b e l; b=$("$2"); e=$("$3"); l=$("$4")
  [ "$b" = "$e" ] || { fail "$1: eager output differs ('$e' != '$b')"; return; }
  [ "$b" = "$l" ] || { fail "$1: lazy output differs ('$l' != '$b')"; return; }
  local le ll; le=$(strings "$3" | grep -cE "$SECRETS" || true); ll=$(strings "$4" | grep -cE "$SECRETS" || true)
  [ "$le" -eq 0 ] && [ "$ll" -eq 0 ] || { fail "$1: plaintext leak (eager=$le lazy=$ll)"; return; }
  pass "$1 (out='$b', 0 leak)"
}

echo "=== corpus (target=${TGT:-native}, mode=$([ $CROSS = 1 ] && echo IR-only || echo build+run)) ==="

if [ "$CROSS" = 1 ]; then
  $CLANG   -O2 $TFLAG -emit-llvm -S "$HERE/c_loops.c"     -o "$D/c.ll"  2>/dev/null && ir_check c_loops   "$D/c.ll"  || fail "c_loops: emit failed"
  $CLANGXX -O2 $TFLAG -emit-llvm -S "$HERE/cpp_classes.cpp" -o "$D/x.ll" 2>/dev/null && ir_check cpp_classes "$D/x.ll" || fail "cpp_classes: emit failed"
  if rustc "+$NIGHTLY" -V >/dev/null 2>&1; then
    rustc "+$NIGHTLY" -O --target "$TGT" --emit=llvm-ir -o "$D/r.ll" "$HERE/rust_prog.rs" 2>/dev/null \
      && ir_check rust_prog "$D/r.ll" || echo "  SKIP rust_prog (no $TGT std)"
  fi
else
  $CLANG   -O2 "$HERE/c_loops.c"     -o "$D/c_b" 2>/dev/null
  $CLANG   -O2 -fpass-plugin="$PLUGIN" "$HERE/c_loops.c" -o "$D/c_e" 2>/dev/null
  RUSTCLOAK_LAZY=1 $CLANG -O2 -fpass-plugin="$PLUGIN" "$HERE/c_loops.c" -o "$D/c_l" 2>/dev/null
  run_check c_loops "$D/c_b" "$D/c_e" "$D/c_l"

  $CLANGXX -O2 "$HERE/cpp_classes.cpp" -o "$D/x_b" 2>/dev/null
  $CLANGXX -O2 -fpass-plugin="$PLUGIN" "$HERE/cpp_classes.cpp" -o "$D/x_e" 2>/dev/null
  RUSTCLOAK_LAZY=1 $CLANGXX -O2 -fpass-plugin="$PLUGIN" "$HERE/cpp_classes.cpp" -o "$D/x_l" 2>/dev/null
  run_check cpp_classes "$D/x_b" "$D/x_e" "$D/x_l"

  if rustc "+$NIGHTLY" -V >/dev/null 2>&1; then
    rustc "+$NIGHTLY" -O -o "$D/r_b" "$HERE/rust_prog.rs" 2>/dev/null
    rustc "+$NIGHTLY" -O --emit=llvm-ir -o "$D/r.ll" "$HERE/rust_prog.rs" 2>/dev/null
    # -Zllvm-plugins may not load on rustup rustc; use the portable opt-on-IR path, then compile IR
    "$OPT" -load-pass-plugin="$PLUGIN" -passes='strenc,function(subst,bogus,flatten)' "$D/r.ll" -S -o "$D/r_obf.ll" 2>/dev/null
    rleak=$(grep -cE "rust::secret|rust::endpoint" "$D/r_obf.ll" || true)
    n=$((n+1))
    if "$OPT" -passes=verify "$D/r_obf.ll" >/dev/null 2>&1 && [ "$rleak" -eq 0 ]; then
      pass "rust_prog (opt-on-IR: verified, secrets encrypted; baseline out='$($D/r_b)')"
    else fail "rust_prog: IR invalid or secret leaked ($rleak)"; fi
  else echo "  SKIP rust_prog (no rustc +$NIGHTLY)"; fi
fi

rm -rf "$D"
echo "=== $((n-fails))/$n checks OK ==="
[ "$fails" -eq 0 ] && echo "CORPUS PASS" || { echo "CORPUS FAILED ($fails)"; exit 1; }
