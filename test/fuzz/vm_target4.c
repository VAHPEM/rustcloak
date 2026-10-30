// Fourth differential corpus: exercises INDIRECT calls (OP_CALLV). The trampolines run()/runf()
// take an opaque function-pointer PARAMETER, so -O2 cannot devirtualize the call inside them; they
// are virt-eligible (indirect call + return over lane-typed values) and thus virtualized, putting
// the indirect typed-call path on the hot path for two distinct signatures: int(int,int) and
// float(float). `compute` itself stays native (it selects among function constants), and folds a
// u64 as usual. UB-free so baseline must equal the virtualized build bit-for-bit.
#include <stdint.h>
#include <stddef.h>
typedef int   (*binop)(int, int);
typedef float (*ffp)(float);

__attribute__((noinline)) static int addf(int a, int b) { return (int)((uint32_t)a + (uint32_t)b); }
__attribute__((noinline)) static int subf(int a, int b) { return (int)((uint32_t)a - (uint32_t)b); }
__attribute__((noinline)) static int xorf(int a, int b) { return a ^ b; }
__attribute__((noinline)) static float sq(float x) { return x * x - 1.0f; }
__attribute__((noinline)) static float hl(float x) { return x * 0.5f + 2.0f; }

__attribute__((noinline)) static int   run (binop fp, int a, int b) { return fp(a, b); }  // virtualized
__attribute__((noinline)) static float runf(ffp  fp, float x)       { return fp(x); }     // virtualized

uint64_t compute(const uint8_t *data, size_t len) {
    uint64_t acc = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        uint64_t x = acc ^ ((uint64_t)data[i] + i * 0x100000001b3ULL);
        binop b = (x & 1) ? addf : ((x & 2) ? subf : xorf);
        acc ^= (uint64_t)(uint32_t)run(b, (int)x, (int)(x >> 7));
        ffp f = (x & 4) ? sq : hl;
        float r = runf(f, (float)(int)(x & 0x3f));
        acc += (uint64_t)(int64_t)(r * 11.0f);
        acc = acc * 65599u + 0x9e3779b9u;
    }
    return acc;
}
