// Functions that the round-1 VM can virtualize: single-block integer computation
// (arithmetic, comparisons, select) -- the kind of key mixers / checks that matter.
#include <stdio.h>
#include <stdint.h>

// a little bit-mixer (the shape of a hash/key-schedule step)
__attribute__((noinline))
uint32_t mix(uint32_t x, uint32_t y) {
    uint32_t a = (x ^ 0x9e3779b9u) + (y << 7);
    uint32_t b = (a * 0x85ebca6bu) ^ (a >> 13);
    uint32_t c = b - (x | 0x1234u);
    return (c & 0xffffu) | ((a ^ b) << 16);
}

// a licence-style check: a branchless predicate reduced to arithmetic + select
__attribute__((noinline))
int check(int serial, int salt) {
    int t = (serial * 31 + salt) ^ (serial >> 3);
    int ok = (t % 97 == 0) & (serial > 1000);
    return ok ? serial + salt : -1;
}

// 64-bit arithmetic path
__attribute__((noinline))
uint64_t fold64(uint64_t h, uint64_t v) {
    h ^= v;
    h *= 0x100000001b3ull;
    h = (h << 23) | (h >> 41);
    return h + (v & 0xffull);
}

// a scalar LOOP with an in-loop branch (no memory) -- exercises control-flow virtualization
__attribute__((noinline))
uint32_t crc_ish(uint32_t x, uint32_t n) {
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < n; i++) {
        h ^= (x + i);
        h *= 16777619u;
        if (h & 1u)
            h ^= 0x5bd1e995u;
    }
    return h;
}

// a real buffer routine: XOR-decode ct[] into out[] with a 4-byte key -- loads, stores,
// pointer indexing, mixed widths (i8 bytes, i32 index). All pointers are arguments (no globals).
__attribute__((noinline))
void decode(unsigned char *out, const unsigned char *ct, int len, const unsigned char *key) {
    for (int i = 0; i < len; i++)
        out[i] = (unsigned char)(ct[i] ^ key[i & 3]);
}

// a scalar accumulator that READS a buffer and returns a value (load + loop + arithmetic)
__attribute__((noinline))
uint32_t sum_mix(const uint32_t *p, int n) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) {
        h = (h ^ p[i]) * 16777619u;
        h ^= h >> 15;
    }
    return h;
}

// a STORE-heavy routine with a loop-carried dependency (so it won't auto-vectorize): a running
// rolling-xor written byte by byte into out[]. Exercises LOAD + STORE + GEP in the VM.
__attribute__((noinline))
void roll(unsigned char *out, const unsigned char *in, int n) {
    unsigned char acc = 0x3b;
    for (int i = 0; i < n; i++) {
        acc = (unsigned char)(acc * 31 + in[i]);   // loop-carried: no vectorization, no intrinsic
        out[i] = acc;
    }
}

// a non-inlined helper, and a function that CALLS it twice -- exercises call virtualization
__attribute__((noinline))
uint32_t helper(uint32_t a, uint32_t b) { return a * b + (a ^ b); }

__attribute__((noinline))
uint32_t wrap(uint32_t x, uint32_t y) { return helper(x, y) + helper(y, x) * 3; }

int main(int argc, char **argv) {
    if (argc > 1) {                       // stress mode: fold many inputs into one checksum
        unsigned long long acc = 0;
        unsigned char buf[256], out[256];
        unsigned key[1] = {0};
        unsigned char *kb = (unsigned char *)key;
        for (unsigned i = 0; i < 20000; i++) {
            unsigned x = i * 2654435761u, y = (i ^ 0x5a5a5a5au) + 7;
            acc ^= mix(x, y);
            acc = acc * 31 + (unsigned)check((int)x, (int)y);
            acc ^= fold64(acc, (unsigned long long)x << 13 | y);
            acc += crc_ish(x, i % 200);
            // memory path: fill a buffer, decode it, read it back
            int n = (i % 200) + 1;
            for (int j = 0; j < n; j++) buf[j] = (unsigned char)(x >> (j & 7)) + j;
            key[0] = x ^ y;
            decode(out, buf, n, kb);
            acc ^= sum_mix((const uint32_t *)out, n / 4);
            for (int j = 0; j < n; j++) acc += out[j];
            unsigned char rolled[256];
            roll(rolled, out, n);         // STORE path (virtualized)
            for (int j = 0; j < n; j++) acc = acc * 65599 + rolled[j];
            acc ^= wrap(x, y);            // CALL path (virtualized)
        }
        printf("stress=%llu\n", acc);
        return 0;
    }
    printf("mix=%u\n", mix(0xdeadbeefu, 0x12345678u));
    printf("check=%d\n", check(1234567, 42));
    printf("fold64=%llu\n", (unsigned long long)fold64(0xcbf29ce484222325ull, 0x61626364ull));
    printf("crc_ish=%u\n", crc_ish(0xcafef00du, 50));
    return 0;
}
