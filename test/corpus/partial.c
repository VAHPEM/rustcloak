#include <stdio.h>
#include <stdint.h>
// mix() is NOT wholly virt-eligible (the vararg printf call), but the if-block is a clean
// single-successor integer region the partial pass can outline into its own function and virtualize.
__attribute__((noinline)) uint32_t mix(uint32_t a, uint32_t b, int cond) {
    uint32_t x = a ^ b;
    if (cond) {
        x = x * 2654435761u;
        x ^= x >> 13;
        x += (b | 7u) * 3u;
        x = (x << 5) | (x >> 27);
        x -= a;
    }
    printf("[%u:%u]", x, b);   // vararg -> whole-function virt ineligible
    return x + b;
}
int main(void) { printf("p=%u\n", mix(123456789u, 987654321u, 1)); return 0; }
