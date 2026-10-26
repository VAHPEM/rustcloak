// Selective-virtualization fixture (test/select.sh). Five functions, all eligible for `virt`:
// two with security-sensitive names, two ordinary, and one ordinary-named but explicitly annotated
// for virtualization. The test counts how many are virtualized in each selection mode.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// sensitive by name heuristic ("licen"+"check", "crypt")
__attribute__((noinline)) uint32_t license_check(uint32_t serial, uint32_t salt) {
    uint32_t t = (serial * 31u + salt) ^ (serial >> 3);
    return (t % 97u == 0u) ? serial + salt : 0xffffffffu;
}
__attribute__((noinline)) uint32_t crypt_round(uint32_t x, uint32_t k) {
    uint32_t a = (x ^ 0x9e3779b9u) + (k << 7);
    return (a * 0x85ebca6bu) ^ (a >> 13);
}

// ordinary names (no heuristic keyword)
__attribute__((noinline)) uint32_t add_helper(uint32_t a, uint32_t b) {
    return a * b + (a ^ b);
}
__attribute__((noinline)) uint32_t scale_values(uint32_t x, uint32_t n) {
    uint32_t h = 0u;
    for (uint32_t i = 0; i < n; i++) h = h * 65599u + (x + i);
    return h;
}

// ordinary name, but explicitly opted in: must be virtualized in every mode
__attribute__((annotate("rustcloak_vm"), noinline))
uint32_t plain_but_marked(uint32_t x, uint32_t y) {
    return (x + y) * 2654435761u;
}

int main(int argc, char **argv) {
    uint32_t s = argc > 1 ? (uint32_t)strtoul(argv[1], 0, 0) : 1234567u;
    uint32_t acc = license_check(s, 42u);
    acc ^= crypt_round(acc, s);
    acc += add_helper(acc, s);
    acc ^= scale_values(acc, 50u);
    acc += plain_but_marked(acc, s);
    printf("%u\n", acc);
    return 0;
}
