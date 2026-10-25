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

int main(void) {
    printf("mix=%u\n", mix(0xdeadbeefu, 0x12345678u));
    printf("check=%d\n", check(1234567, 42));
    printf("fold64=%llu\n", (unsigned long long)fold64(0xcbf29ce484222325ull, 0x61626364ull));
    return 0;
}
