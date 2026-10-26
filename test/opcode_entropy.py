#!/usr/bin/env python3
# Opcode-frequency analysis of a RustCloak `virt` bytecode blob. Given a virt-only .ll, find the
# largest internal `[N x i8]` array (the bytecode of one virtualized function), take every 4th byte
# (the opcode byte -- instructions are 4 bytes: opcode, dst, a, b), and report how resistant it is
# to opcode frequency analysis: the number of distinct opcode bytes (= interpreter handlers), the
# Shannon entropy of the opcode distribution, and the share of the single most common opcode. With
# synonym opcodes a logical op is spread over several bytes, so entropy is higher and the max share
# lower than a one-byte-per-op encoding.
import sys, re, math
from collections import Counter

ll = open(sys.argv[1]).read()
best = None
for m in re.finditer(r'\[(\d+) x i8\]\s+c"((?:[^"\\]|\\[0-9A-Fa-f][0-9A-Fa-f]|\\\\)*)"', ll):
    n = int(m.group(1))
    if best is None or n > best[0]:
        best = (n, m.group(2))
if not best:
    print("no i8 array found")
    sys.exit(0)

lit = best[1]
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

ops = out[0::4]
tot = len(ops)
if tot == 0:
    print("empty"); sys.exit(0)
h = Counter(ops)
ent = -sum((c / tot) * math.log2(c / tot) for c in h.values())
maxshare = max(h.values()) / tot
print(f"bytecode_bytes={len(out)} instrs={tot} "
      f"distinct_opcodes(handlers)={len(h)} opcode_entropy_bits={ent:.2f} "
      f"max_single_opcode_share={maxshare * 100:.1f}%")
