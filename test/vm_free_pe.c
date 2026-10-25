typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

__declspec(dllexport) uint32_t mix(uint32_t x, uint32_t y) {
    uint32_t a = (x ^ 0x9e3779b9u) + (y << 7);
    uint32_t b = (a * 0x85ebca6bu) ^ (a >> 13);
    uint32_t c = b - (x | 0x1234u);
    return c ^ (c >> 16);
}
__declspec(dllexport) uint64_t fold64(uint64_t h, uint64_t v) {
    h ^= v; h *= 0x100000001b3ULL; h ^= h >> 32; return h;
}
__declspec(dllexport) uint32_t crc_ish(uint32_t x, uint32_t n) {
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < n; i++) { h = (h ^ (x + i)) * 0x01000193u; if (h & 1) h ^= 0x5bd1e995u; }
    return h;
}
