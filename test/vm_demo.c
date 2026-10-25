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

int main(int argc, char **argv) {
    if (argc > 1) {                       // stress mode: fold many inputs into one checksum
        unsigned long long acc = 0;
        for (unsigned i = 0; i < 20000; i++) {
            unsigned x = i * 2654435761u, y = (i ^ 0x5a5a5a5au) + 7;
            acc ^= mix(x, y);
            acc = acc * 31 + (unsigned)check((int)x, (int)y);
            acc ^= fold64(acc, (unsigned long long)x << 13 | y);
            acc += crc_ish(x, i % 200);
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
