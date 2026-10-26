// Single virtualizable function, for the anti-tamper demonstration (test/tamper.sh): exactly one
// `virt` bytecode blob is emitted, so the test can locate it unambiguously, flip individual bytes,
// and measure whether the integrity self-hash catches the tamper. `keycheck` has the shape of a
// licence/key mixer -- the kind of routine worth virtualizing and protecting.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

__attribute__((noinline)) uint32_t keycheck(uint32_t x, uint32_t y) {
    uint32_t a = (x ^ 0x9e3779b9u) + (y << 7);
    uint32_t b = (a * 0x85ebca6bu) ^ (a >> 13);
    uint32_t c = b - (x | 0x1234u);
    return (c & 0xffffu) | ((a ^ b) << 16);
}

int main(int argc, char **argv) {
    uint32_t y = argc > 1 ? (uint32_t)strtoul(argv[1], 0, 0) : 0x12345678u;
    printf("%u\n", keycheck(0xdeadbeefu, y));
    return 0;
}
