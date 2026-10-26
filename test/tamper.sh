#!/usr/bin/env bash
# Anti-tamper demonstration for RUSTCLOAK_VM_INTEGRITY, targeting the VM bytecode precisely.
#
# A single-function program (test/vm_one.c) is virtualized so exactly one bytecode blob exists. We
# read that blob's exact bytes straight out of the `virt` IR, compile the SAME IR to an executable,
# locate the byte run in the file, and flip EACH byte in turn -- re-running after every flip.
#
#   without integrity : a flipped operand/opcode byte perturbs one instruction; many flips leave the
#                        observable output unchanged (the byte fed a masked lane, an unused dst, ...).
#   with integrity    : the interpreter hashes its own bytecode and folds the hash into the operand-
#                        decryption keys, so ANY flipped byte corrupts every later operand decode and
#                        the program diverges or crashes -- with no integrity-compare branch to NOP.
#
# PASS requires that integrity catches 100% of single-byte bytecode flips and strictly more than the
# unprotected build. "Measure before you conclude": the gap between the two rates is the protection.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG=${CLANG:-clang-18}; OPT=${OPT:-opt-18}; LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
export RUSTCLOAK_SEED=${RUSTCLOAK_SEED:-0x51ab1ec0de}
PLUGIN=build/libRustCloak.so
SRC=${SRC:-test/vm_one.c}
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

echo "== build plugin =="
cmake -S . -B build -G Ninja -DLLVM_DIR="$($LLVM_CONFIG --cmakedir)" >/dev/null 2>&1 || true
cmake --build build >/dev/null

$CLANG -O1 -fno-discard-value-names -emit-llvm -S "$SRC" -o "$WORK/base.ll"
$CLANG -O2 "$WORK/base.ll" -o "$WORK/golden" 2>/dev/null
GOLDEN=$("$WORK/golden"); echo "  golden output: $GOLDEN"

# Flip every byte of the bytecode blob of a virt build and print "caught/total".
#   $1 = extra env for the virt pass (e.g. RUSTCLOAK_VM_INTEGRITY=1)
probe() {
  env $1 RUSTCLOAK_VM=1 $OPT -load-pass-plugin=$PLUGIN -passes='function(virt)' \
      "$WORK/base.ll" -S -o "$WORK/v.ll" 2>/dev/null
  $CLANG -O2 "$WORK/v.ll" -o "$WORK/v" 2>/dev/null
  python3 - "$WORK/v.ll" "$WORK/v" "$GOLDEN" <<'PY'
import sys, re, subprocess, os
llpath, binpath, golden = sys.argv[1], sys.argv[2], sys.argv[3]
ll = open(llpath).read()
# largest internal i8 array initializer == the one virtualized function's bytecode
best = None
for m in re.finditer(r'\[(\d+) x i8\]\s+c"((?:[^"\\]|\\[0-9A-Fa-f][0-9A-Fa-f]|\\\\)*)"', ll):
    n = int(m.group(1))
    if best is None or n > best[0]: best = (n, m.group(2))
lit = best[1]; blob = bytearray(); i = 0
while i < len(lit):
    if lit[i] == '\\':
        if lit[i+1] == '\\': blob.append(0x5c); i += 2
        else: blob.append(int(lit[i+1:i+3], 16)); i += 3
    else: blob.append(ord(lit[i])); i += 1
data = open(binpath, 'rb').read()
off = data.find(bytes(blob))
if off < 0 or data.find(bytes(blob), off+1) != -1:
    print("ERR: bytecode run not uniquely locatable", file=sys.stderr); print("0/0"); sys.exit(0)
caught = 0
for k in range(len(blob)):
    b = bytearray(data); b[off+k] ^= 0x55
    tf = binpath + ".t"; open(tf, 'wb').write(b); os.chmod(tf, 0o755)
    try:
        r = subprocess.run([tf], capture_output=True, text=True, timeout=15)
        diverged = (r.returncode != 0) or (r.stdout.strip() != golden.strip())
    except subprocess.TimeoutExpired:
        diverged = True
    caught += 1 if diverged else 0
    os.remove(tf)
print(f"{caught}/{len(blob)}")
PY
}

echo "== WITHOUT integrity =="; noi=$(probe ""); echo "  single-byte bytecode flips detected: $noi"
echo "== WITH integrity    =="; wi=$(probe "RUSTCLOAK_VM_INTEGRITY=1"); echo "  single-byte bytecode flips detected: $wi"

in=${wi%/*}; it=${wi#*/}; cn=${noi%/*}
echo
echo "== result =="
echo "  without integrity: $noi"
echo "  with integrity   : $wi"
[ "$it" -gt 0 ] && [ "$in" = "$it" ] && [ "$in" -gt "$cn" ] \
  && echo "TAMPER PASS: integrity catches every single-byte bytecode flip (unprotected missed $((it-cn)))" \
  || { echo "TAMPER FAILED"; exit 1; }
