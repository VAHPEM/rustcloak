#!/usr/bin/env bash
# Cross-architecture / cross-format test matrix for RustCloak -- the "test it on the other VMs and
# the other CPU" gate the project asks for, made concrete and hermetic on a single Linux host:
#
#   linux-x64    native clang                              run: direct
#   linux-arm64  clang --target=aarch64-linux-gnu + gcc    run: qemu-aarch64-static   (ARM)
#   win-x64      clang --target=x86_64-w64-windows-gnu      run: wine                  (Windows PE)
#
# A target whose toolchain or emulator is absent is reported SKIP, never a silent pass, so the output
# always states exactly which {OS-format, CPU} pairs were actually exercised -- "an architecture not
# tested is said so." The obfuscation is an LLVM-IR transform, so correct behaviour on these three
# {ELF x86-64, ELF AArch64, PE x86-64} is strong evidence it is correct on every target of that IR;
# the machine code the interpreter lowers to differs per arch, which is the point of running all three.
#
# For each live target:
#   1. program differential -- build each test program twice (baseline / RUSTCLOAK_VM=1 full -O2
#      pipeline) at a FIXED RUSTCLOAK_SEED, run on a fixed input set, require identical stdout + rc.
#   2. differential fuzz    -- build one self-contained binary (test/fuzz/vm_selfdiff.c) holding both
#      the baseline and the virtualized `compute`, run FUZZ_ITERS xorshift inputs through both.
#
# Env: RUSTCLOAK_SEED (fixed below), FUZZ_ITERS (per-target self-diff iterations), ONLY=<t1,t2> to
# restrict targets. Exit non-zero on any divergence, miscompile, or build failure of a live target.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
# Default kept modest because the emulated targets (qemu/wine) run the fuzzer orders of magnitude
# slower than native; raise it for a soak run, or use ONLY=linux-x64 for a fast native-only pass.
FUZZ_ITERS=${FUZZ_ITERS:-50000}
PLUGIN="$(pwd)/build/libRustCloak.so"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WINEDEBUG=${WINEDEBUG:--all} WINEPREFIX=${WINEPREFIX:-$WORK/wine}

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null
[ -f "$PLUGIN" ] || { echo "FATAL: plugin not built"; exit 1; }

# A target is (name, clang-target-triple, link-command, run-command). The link command turns an
# object (or several) into a runnable file; the run command executes it. Empty triple = native.
have() { command -v "$1" >/dev/null 2>&1; }
targets=()
target_meta() {        # name -> "triple|linker|runner|ext"; "" if unavailable
  case "$1" in
    linux-x64)   echo "|$CLANG|direct|";;
    linux-arm64) have aarch64-linux-gnu-gcc && have qemu-aarch64-static \
                   && echo "aarch64-linux-gnu|aarch64-linux-gnu-gcc -static|qemu-aarch64-static|";;
    win-x64)     have x86_64-w64-mingw32-gcc && have wine \
                   && echo "x86_64-w64-windows-gnu|x86_64-w64-mingw32-gcc -static|wine|.exe";;
  esac
}
ALL="linux-x64 linux-arm64 win-x64"
SEL="${ONLY:-$ALL}"; SEL="${SEL//,/ }"

# compile one source to an object for a triple, optionally with the obfuscator plugin
compile() { # triple obf src out [extra-cflags...]
  local triple=$1 obf=$2 src=$3 out=$4; shift 4
  local t=(); [ -n "$triple" ] && t=(--target="$triple")
  if [ "$obf" = obf ]; then
    RUSTCLOAK_VM=1 $CLANG "${t[@]}" -O2 -fpass-plugin="$PLUGIN" -c "$src" -o "$out" "$@"
  else
    $CLANG "${t[@]}" -O2 -c "$src" -o "$out" "$@"
  fi
}
run() { # runner binary [args...]
  local runner=$1 bin=$2; shift 2
  if [ "$runner" = direct ]; then "$bin" "$@"; else $runner "$bin" "$@"; fi
}

overall=0; summary=""
for name in $SEL; do
  meta=$(target_meta "$name")
  if [ -z "$meta" ]; then
    printf "\n### %-12s SKIP (toolchain/emulator missing)\n" "$name"
    summary+=$'\n'"  $name: SKIP"
    continue
  fi
  IFS='|' read -r triple linker runner ext <<<"$meta"
  printf "\n### %-12s triple='%s' run='%s'\n" "$name" "${triple:-native}" "$runner"
  tfail=0

  # ---- 1. program differential ----
  # each: "src|compiler-is-cpp|arg1;arg2;..." (args separated by ';', empty = one no-arg run)
  progs=(
    "test/demo.c|0|"
    "test/vm_demo.c|0|;stress"
    "test/vm_nested.c|0|;a b c"
    "test/corpus/c_loops.c|0|"
  )
  for spec in "${progs[@]}"; do
    IFS='|' read -r src _cpp argspec <<<"$spec"
    pname=$(basename "$src")
    base_o="$WORK/${name}_${pname}_b.o" obf_o="$WORK/${name}_${pname}_o.o"
    base_x="$WORK/${name}_${pname}_b$ext" obf_x="$WORK/${name}_${pname}_o$ext"
    if ! compile "$triple" base "$src" "$base_o" 2>"$WORK/err" \
       || ! $linker "$base_o" -o "$base_x" 2>>"$WORK/err"; then
      echo "  FAIL $pname: baseline build"; sed 's/^/      /' "$WORK/err"|tail -3; tfail=1; continue
    fi
    if ! compile "$triple" obf "$src" "$obf_o" 2>"$WORK/err" \
       || ! $linker "$obf_o" -o "$obf_x" 2>>"$WORK/err"; then
      echo "  FAIL $pname: obfuscated build"; sed 's/^/      /' "$WORK/err"|tail -3; tfail=1; continue
    fi
    bad=0; IFS=';' read -ra args <<<"$argspec"
    [ ${#args[@]} -eq 0 ] && args=("")
    for a in "${args[@]}"; do
      bo=$(run "$runner" "$base_x" $a 2>/dev/null | tr -d '\r'); bx=$?
      oo=$(run "$runner" "$obf_x"  $a 2>/dev/null | tr -d '\r'); ox=$?
      [ "$bo" = "$oo" ] && [ "$bx" = "$ox" ] || {
        echo "  FAIL $pname [args='$a']: base(rc=$bx)='$bo' != obf(rc=$ox)='$oo'"; bad=1; }
    done
    [ $bad = 0 ] && echo "  OK   $pname" || tfail=1
  done

  # ---- 2. differential fuzz (self-contained, no dlopen) ----
  bo="$WORK/${name}_vt_base.o" vo="$WORK/${name}_vt_virt.o" do_="$WORK/${name}_sd.o"
  fx="$WORK/${name}_selfdiff$ext"
  if compile "$triple" base test/fuzz/vm_target.c "$bo" -Dcompute=compute_base 2>"$WORK/err" \
     && compile "$triple" obf  test/fuzz/vm_target.c "$vo" -Dcompute=compute_virt 2>>"$WORK/err" \
     && compile "$triple" base test/fuzz/vm_selfdiff.c "$do_" 2>>"$WORK/err" \
     && $linker "$bo" "$vo" "$do_" -o "$fx" 2>>"$WORK/err"; then
    out=$(run "$runner" "$fx" "$FUZZ_ITERS" 2>/dev/null | tr -d '\r')
    if echo "$out" | grep -q '^OK:'; then echo "  OK   vm-selfdiff-fuzz ($out)"
    else echo "  FAIL vm-selfdiff-fuzz: $out"; tfail=1; fi
  else
    echo "  FAIL vm-selfdiff-fuzz: build"; sed 's/^/      /' "$WORK/err"|tail -3; tfail=1
  fi

  [ $tfail = 0 ] && summary+=$'\n'"  $name: PASS" || { summary+=$'\n'"  $name: FAIL"; overall=1; }
done

echo
echo "== matrix summary (seed=$RUSTCLOAK_SEED, fuzz_iters=$FUZZ_ITERS) =="
echo "$summary"
echo
[ $overall = 0 ] && echo "MATRIX PASS" || { echo "MATRIX FAILED"; exit 1; }
