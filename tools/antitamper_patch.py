#!/usr/bin/env python3
"""Post-link patcher for RustCloak RUSTCLOAK_ANTITAMPER builds (ELF64).

Finds the integrity descriptor by its 8-byte magic, reads the protected section's name from it,
FNV-1a-hashes that section's on-disk bytes (identical to the in-memory bytes for a PIE code section),
and writes the hash into the descriptor's `expected` field. Run once on the linked binary before
shipping -- an unpatched ANTITAMPER build deliberately misbehaves.

Usage:
  antitamper_patch.py <binary>              patch `expected` with the real section hash
  antitamper_patch.py --flip-last <binary>  flip the last protected-section byte (tamper, for tests)
"""
import sys, struct

RC_AT_MAGIC = 0x52435f41545f4d31          # must match AntiTamper.cpp
FNV_OFFSET  = 0xcbf29ce484222325
FNV_PRIME   = 0x100000001b3
MASK        = (1 << 64) - 1

def fnv(b):
    h = FNV_OFFSET
    for x in b:
        h = ((h ^ x) * FNV_PRIME) & MASK
    return h

def sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("not an ELF64 file")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        secs.append((name, off, size))
    shstr_off = secs[e_shstrndx][1]
    def nm(n):
        end = data.index(0, shstr_off + n)
        return data[shstr_off + n:end].decode("latin1")
    return {nm(n): (off, size) for (n, off, size) in secs}

def find_descriptor(data):
    """Return (desc_file_offset, section_name) for the integrity descriptor, or None."""
    mg = struct.pack("<Q", RC_AT_MAGIC)
    byname = sections(data)
    pos = 0
    while True:
        idx = data.find(mg, pos)
        if idx < 0:
            return None
        pos = idx + 1
        try:
            namelen = struct.unpack_from("<Q", data, idx + 16)[0]
            if 0 < namelen <= 31:
                name = bytes(data[idx + 24:idx + 24 + namelen]).decode("latin1")
                if name in byname:
                    return idx, name
        except Exception:
            pass

def main(argv):
    flip = False
    args = argv[1:]
    if args and args[0] == "--flip-last":
        flip = True
        args = args[1:]
    if len(args) != 1:
        raise SystemExit(__doc__)
    path = args[0]
    data = bytearray(open(path, "rb").read())
    found = find_descriptor(data)
    if not found:
        print("no antitamper descriptor found (not an ANTITAMPER build?)")
        return 2
    desc_off, secname = found
    off, size = sections(data)[secname]
    if flip:
        data[off + size - 1] ^= 0xFF
        open(path, "wb").write(data)
        print("flipped last byte of section %s (now tampered)" % secname)
        return 0
    H = fnv(data[off:off + size])
    struct.pack_into("<Q", data, desc_off + 8, H)   # expected is descriptor field #2 (offset 8)
    open(path, "wb").write(data)
    print("patched: section=%s size=%d fnv=%016x" % (secname, size, H))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
