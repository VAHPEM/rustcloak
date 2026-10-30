#!/usr/bin/env bash
# Behavioural (RUN, not just object-level) matrix for Mach-O. The arch/format object check in
# test/matrix_freestanding.sh emits Mach-O objects and verifies their IR, but cannot RUN them off a
# macOS host. This script closes that gap on Apple hardware: it builds the `virt` differential
# self-checker (test/fuzz/vm_selfdiff.c, baseline vs RUSTCLOAK_VM=1 folded into one binary) as a
# native Mach-O and runs it, requiring base == virt. On anything that is not macOS it SKIPs loudly,
# never a silent pass.
#
#   aarch64-apple-darwin : native run
#   x86_64-apple-darwin  : run via Rosetta 2 (`arch -x86_64`) on Apple Silicon, else object-only
#
# Needs a macOS-built plugin: build libRustCloak.so with macOS LLVM 18 (e.g. Homebrew llvm@18) and
# point RUSTCLOAK_PLUGIN at it, or let the default repo build/ path be used.
set -uo pipefail
cd "$(dirname "$0")/.."
FUZZ=test/fuzz
PLUGIN="${RUSTCLOAK_PLUGIN:-$PWD/build/libRustCloak.so}"
CLANG="${CLANG:-clang-18}"; OPT="${OPT:-opt-18}"
export RUSTCLOAK_SEED="${RUSTCLOAK_SEED:-0x51ab1ec0de}"
ITERS="${ITERS:-200000}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "SKIP matrix_macho: not a macOS host (this is $(uname -s)); object-level Mach-O is covered by matrix_freestanding.sh"
  exit 0
fi
command -v "$CLANG" >/dev/null 2>&1 || { echo "SKIP matrix_macho: no $CLANG on this host"; exit 0; }
[ -f "$PLUGIN" ] || { echo "SKIP matrix_macho: no plugin at $PLUGIN (build it with macOS LLVM 18)"; exit 0; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
rc=0

run_target() { # name  clang-target  runner...
  local name="$1" triple="$2"; shift 2
  local runner=("$@")
  local bo="$WORK/base_$name.o" vo="$WORK/virt_$name.o" bin="$WORK/sd_$name"
  if ! $CLANG -O2 --target="$triple" -c "$FUZZ/vm_target.c" -Dcompute=compute_base -o "$bo" 2>"$WORK/e"; then
    printf "  %-22s build fail (baseline): %s\n" "$name" "$(head -1 "$WORK/e")"; rc=1; return; fi
  if ! RUSTCLOAK_VM=1 $CLANG -O2 --target="$triple" -fpass-plugin="$PLUGIN" -c "$FUZZ/vm_target.c" \
        -Dcompute=compute_virt -o "$vo" 2>"$WORK/e"; then
    printf "  %-22s build fail (virt): %s\n" "$name" "$(head -1 "$WORK/e")"; rc=1; return; fi
  local fmt; fmt=$(file -b "$vo" | cut -c1-30)
  if ! $CLANG --target="$triple" "$bo" "$vo" "$FUZZ/vm_selfdiff.c" -o "$bin" 2>"$WORK/e"; then
    printf "  %-22s object OK [%s]  (no linker/runtime to RUN here)\n" "$name" "$fmt"; return; fi
  if [ "${#runner[@]}" -eq 0 ]; then
    printf "  %-22s object OK [%s]  (no runner)\n" "$name" "$fmt"; return; fi
  local out; out=$("${runner[@]}" "$bin" "$ITERS" 2>&1); local ec=$?
  printf "  %-22s [%s]  %s\n" "$name" "$fmt" "$out"
  [ $ec -eq 0 ] || rc=1
}

echo "== Mach-O behavioural matrix (RUSTCLOAK_SEED=$RUSTCLOAK_SEED, $ITERS iters) =="
HOSTARCH=$(uname -m)
run_target aarch64-apple-darwin arm64-apple-macos
if command -v arch >/dev/null 2>&1 && [ "$HOSTARCH" = "arm64" ]; then
  run_target x86_64-apple-darwin x86_64-apple-macos arch -x86_64
else
  run_target x86_64-apple-darwin x86_64-apple-macos        # native if on an Intel Mac; else object-only
fi

[ $rc -eq 0 ] && echo "MACHO MATRIX PASS" || echo "MACHO MATRIX FAIL"
exit $rc
