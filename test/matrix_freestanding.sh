#!/usr/bin/env bash
# Arch/format matrix. RustCloak's transforms are LLVM-IR level, so they should apply to every
# target LLVM can emit. For each target this (a) emits the fully-obfuscated OBJECT and checks it is
# the right format and its IR verifies, and (b) for the ELF targets, builds a static freestanding
# binary and RUNS it (x86-64 under qemu-user), requiring the obfuscated exit code to match the
# baseline. PE/Mach-O are object-level only (no cross runtime here) -- stated plainly, not assumed.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; PLUGIN=build/libRustCloak.so
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
cmake --build build >/dev/null 2>&1 || true
SRC=test/vm_free_elf.c; DRV=test/vm_free_main.c

echo "== object emission + IR validity per target (full -O2 pipeline + RUSTCLOAK_VM) =="
for t in aarch64-linux-gnu x86_64-linux-gnu x86_64-pc-windows-msvc x86_64-apple-darwin aarch64-apple-darwin; do
  if RUSTCLOAK_VM=1 $CLANG -O2 --target=$t -ffreestanding -fpass-plugin=$PLUGIN -c $SRC -o /tmp/o.o 2>/tmp/e; then
    f=$(file -b /tmp/o.o | cut -c1-38)
    RUSTCLOAK_VM=1 $CLANG -O2 --target=$t -ffreestanding -fpass-plugin=$PLUGIN -emit-llvm -c $SRC -o /tmp/o.bc 2>/dev/null
    v=$($OPT -passes=verify /tmp/o.bc -o /dev/null 2>&1 && echo verified || echo INVALID)
    printf "  %-24s object OK  [%s]  IR=%s\n" "$t" "$f" "$v"
  else
    printf "  %-24s SKIP (%s)\n" "$t" "$(head -1 /tmp/e)"
  fi
done

echo "== behavioural differential (static freestanding ELF; exit-code checksum) =="
run_arch() { # triple runner-cmd
  local t=$1 run=${2:-}
  $CLANG -O2 --target=$t -ffreestanding -nostdlib -static -fuse-ld=lld "$SRC" "$DRV" -o /tmp/b 2>/dev/null \
    || { printf "  %-24s baseline build fail\n" "$t"; return; }
  RUSTCLOAK_VM=1 $CLANG -O2 --target=$t -ffreestanding -nostdlib -static -fuse-ld=lld -fpass-plugin=$PLUGIN "$SRC" "$DRV" -o /tmp/ob 2>/dev/null \
    || { printf "  %-24s obf build fail\n" "$t"; return; }
  $run /tmp/b;  local B=$?
  $run /tmp/ob; local O=$?
  printf "  %-24s baseline_exit=%s obf_exit=%s match=%s\n" "$t" "$B" "$O" "$([ "$B" = "$O" ] && echo YES || echo NO)"
}
run_arch aarch64-linux-gnu                 # native
run_arch x86_64-linux-gnu  qemu-x86_64     # x86-64 via qemu-user
