// SPDX-License-Identifier: Apache-2.0
// Nested-loop stressors for the rust-deobf relooper (control-flow structuring). Each function is a
// reducible loop nest with scalar arguments, so the emulation devirtualizer can drive it with its
// small-magnitude input vectors (the arguments double as loop counts) and the recovered program can
// be re-executed for verification. Built as a RustCloak VM fixture; run natively only for a sanity
// check.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// A clean doubly-nested loop: both bounds are arguments, so -O2 cannot fully unroll it. The relooper
// should raise this to nested do/while.
uint32_t nested_sum(uint32_t n, uint32_t m) {
    uint32_t acc = 0x811c9dc5u;
    for (uint32_t i = 0; i < n; i++)
        for (uint32_t j = 0; j < m; j++)
            acc = (acc ^ (i * 31u + j)) * 0x01000193u;
    return acc;
}

// A triangular nest: the inner bound depends on the outer index (j <= i). Still reducible, but the
// inner loop's trip count varies per outer iteration.
uint32_t tri_mix(uint32_t n) {
    uint32_t h = 0;
    for (uint32_t i = 0; i < n; i++)
        for (uint32_t j = 0; j <= i; j++)
            h += (i ^ j) * 2654435761u;
    return h;
}

// A nest with an early break out of the inner loop: the break adds a second exit edge to the inner
// loop, which is where a two-peephole relooper is expected to stop structuring (left as if/goto).
uint32_t find_mix(uint32_t n, uint32_t key) {
    uint32_t h = 1u;
    for (uint32_t i = 0; i < n; i++) {
        for (uint32_t j = 0; j < n; j++) {
            h += (i * 0x9e3779b9u) ^ (j + 1u);
            if ((h & 0xffu) == key)
                break;
        }
    }
    return h;
}

int main(int argc, char **argv) {
    uint32_t a = (uint32_t)argc, b = (uint32_t)(argc * 3 + 1);
    volatile uint32_t sink = 0;
    sink ^= nested_sum(a, b);
    sink ^= tri_mix(a + 4);
    sink ^= find_mix(a + 2, b & 0xff);
    printf("%u\n", sink);
    return 0;
}
