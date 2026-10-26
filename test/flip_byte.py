#!/usr/bin/env python3
# Tamper demo helper: flip the last byte of the largest internal [N x i8] array (the virt bytecode)
# in a .ll, re-encoding it in LLVM's c"..." escape form. Used to show RUSTCLOAK_VM_INTEGRITY turns a
# single-byte bytecode patch into total divergence.
import sys, re

f = sys.argv[1]
ll = open(f).read()
best = None
for m in re.finditer(r'\[(\d+) x i8\] c"((?:[^"\\]|\\[0-9A-Fa-f][0-9A-Fa-f]|\\\\)*)"', ll):
    if best is None or int(m.group(1)) > int(best.group(1)):
        best = m

lit = best.group(2)
out = bytearray()
i = 0
while i < len(lit):
    if lit[i] == '\\':
        if lit[i + 1] == '\\':
            out.append(0x5c); i += 2
        else:
            out.append(int(lit[i + 1:i + 3], 16)); i += 3
    else:
        out.append(ord(lit[i])); i += 1

out[-1] ^= 0xFF                      # flip the last bytecode byte

def enc(b):
    if b == 0x22: return '\\22'
    if b == 0x5c: return '\\\\'
    if 0x20 <= b < 0x7f: return chr(b)
    return '\\%02X' % b

newlit = ''.join(enc(b) for b in out)
ll = ll[:best.start(2)] + newlit + ll[best.end(2):]
open(f, 'w').write(ll)
print(f"flipped last byte of a {len(out)}-byte bytecode global")
