// Third differential-fuzzing corpus: exercises the TYPED-call paths the VM gained (float/double
// args, 8 args (>6), and float/double/long returns). Same contract as vm_target.c
// (uint64_t compute(const uint8_t*, size_t), everything folded into one u64). All callees are
// noinline so they stay real calls; `compute` itself is kept virt-eligible (signed int->float casts
// only, FPToSI folds, no alloca/addr-of-local), so RUSTCLOAK_VM=1 virtualizes it and the typed CALL
// switch is on the hot path. UB-free so baseline must equal the virtualized build bit-for-bit.
#include <stdint.h>
#include <stddef.h>

__attribute__((noinline)) static float  f3(float a, float b, float c) {      // 3 float args, float ret
    return a * 1.5f + b - c * 0.25f;
}
__attribute__((noinline)) static double d2(double a, double b) {             // double args, double ret
    return a * a - b + 2.0;
}
__attribute__((noinline)) static int    many8(int a, int b, int c, int d,    // 8 int args (>6)
                                              int e, int f, int g, int h) {
    uint32_t r = ((uint32_t)a ^ (uint32_t)b) + ((uint32_t)c | (uint32_t)d);
    r -= ((uint32_t)e & (uint32_t)f) ^ ((uint32_t)g + (uint32_t)h);
    return (int)r;
}
__attribute__((noinline)) static long   mixed(int a, float b, double c, const uint8_t *p) {
    return (long)a + (long)b + (long)c + (long)(*p);     // mixed int/float/double/ptr args, long ret
}

uint64_t compute(const uint8_t *data, size_t len) {
    uint64_t acc = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        uint64_t x = acc ^ ((uint64_t)data[i] + i * 0x100000001b3ULL);
        float fa = f3((float)(int)(x & 0xff), (float)(int)((x >> 8) & 0xff), 3.0f);
        acc ^= (uint64_t)(int64_t)(fa * 7.0f);
        double dd = d2((double)(int)(x % 997u), (double)(int)((x >> 11) % 997u));
        acc += (uint64_t)(int64_t)dd;
        int m = many8((int)x, (int)(x >> 2), (int)(x >> 4), (int)(x >> 6),
                      (int)(x >> 8), (int)(x >> 10), (int)(x >> 12), (int)(x >> 14));
        acc ^= (uint64_t)(uint32_t)m;
        long mx = mixed((int)(x >> 3), (float)(int)(x & 0x3f), (double)(int)((x >> 5) & 0x3f),
                        data + i);
        acc += (uint64_t)mx;
        acc = acc * 65599u + 0x9e3779b9u;
    }
    return acc;
}
