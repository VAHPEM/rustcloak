#include <stdint.h>
#include <stddef.h>
__attribute__((noinline)) static uint64_t mix(uint64_t h, uint64_t x) {
    h ^= x; h *= 0x100000001b3ULL; h += (h >> 29); return h;
}
uint64_t compute(const uint8_t *data, size_t len) {
    static const char *tbl[4] = {"state::alpha","state::bravo","state::charlie","state::delta"};
    uint64_t h = 1469598103934665603ULL; uint32_t state = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        switch (b & 3) {
            case 0: h = mix(h, (uint64_t)b + i); state ^= b; break;
            case 1: h = h - (uint64_t)(b * 7u); state += b; break;
            case 2: h ^= (h << 7) | (uint64_t)(b & 0x0f); state = (state << 1) | (b & 1u); break;
            default: h = (h & ~(uint64_t)b) | (~h & (uint64_t)b); state -= b; break;
        }
        if ((b & 0x80) && i + 1 < len) {
            uint8_t c = data[i + 1];
            for (int k = 0; k < (c & 7); k++) h = mix(h, (uint64_t)(k ^ c));
        }
        if (state % 5 == 0) h += (uint64_t)(uint8_t)tbl[h & 3][0];
    }
    const char *s = tbl[state & 3];
    for (const char *p = s; *p; p++) h = mix(h, (uint8_t)*p);
    return h ^ ((uint64_t)state << 32);
}
