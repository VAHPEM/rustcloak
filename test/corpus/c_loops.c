// Varied control flow: nested loops, a switch, recursion, a function-pointer dispatch table,
// and several string literals. Deterministic output so obfuscated == baseline can be checked.
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

__attribute__((noinline)) static long fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

__attribute__((noinline)) static long add(long a, long b) { return a + b; }
__attribute__((noinline)) static long mul(long a, long b) { return a * b; }
__attribute__((noinline)) static long sub(long a, long b) { return a - b; }

int main(void) {
    const char *names[] = {"corpus::alpha", "corpus::bravo", "corpus::charlie", "corpus::delta"};
    long (*ops[3])(long, long) = {add, mul, sub};

    uint32_t acc = 0;
    for (int i = 0; i < 4; i++) {
        acc ^= fnv1a(names[i]);
        for (int j = 0; j < 3; j++) {
            switch (j) {               // switch over the op table
            case 0: acc += (uint32_t)ops[j](i, j); break;
            case 1: acc ^= (uint32_t)ops[j](i + 1, j + 1); break;
            default: acc -= (uint32_t)ops[j](i + 2, 1); break;
            }
        }
    }
    long f = fib(20);
    printf("acc=%08x fib20=%ld tag=%s\n", acc, f, names[(acc >> 1) & 3]);
    return 0;
}
