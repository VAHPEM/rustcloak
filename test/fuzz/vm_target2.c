// Second differential-fuzzing corpus for RustCloak's `virt` -- a drop-in alternative to vm_target.c
// (same contract: `uint64_t compute(const uint8_t*, size_t)`, everything folded into one u64).
// It stresses the lowering paths that vm_target.c exercises only lightly, all kept deliberately
// *eligible* for virtualization and all UB-free, so baseline and RUSTCLOAK_VM=1 MUST agree:
//   sdiv_rem   signed division/remainder     (SDIV/SREM width + the INT_MIN/-1 guard stays native)
//   recur      bounded recursion             (CALL into self; loop-carried return)
//   chain3     a->b->c nested calls          (argument-buffer / callee-table depth)
//   varshift   variable-amount shifts        (SHL/LSHR/ASHR with masked counts, width-sensitive)
//   fmath      f32 + f64 arithmetic/compare  (FADD/FSUB/FMUL/FDIV/FEQ..; lane bitcast round-trip)
//   fconv      int<->float conversions       (SITOFP/FPTOSI/FPEXT/FPTRUNC)
//   sel_chain  select ladders                (CMOVNZ lowering of `select`)
#include <stdint.h>
#include <stddef.h>
#include <string.h>

__attribute__((noinline)) static uint64_t sdiv_rem(int64_t a, int64_t b) {
    int64_t d = (b | 1);                 // never 0
    if (d == -1) d = 1;                  // avoid INT64_MIN / -1 UB
    int64_t q = a / d, r = a % d;
    return (uint64_t)q ^ ((uint64_t)r << 1);
}

__attribute__((noinline)) static uint32_t recur(uint32_t n, uint32_t acc) {
    if (n == 0) return acc;
    return recur(n - 1, acc * 1664525u + 1013904223u + n);   // bounded by caller (n<=24)
}

__attribute__((noinline)) static uint32_t c3(uint32_t x) { return (x ^ (x >> 7)) * 2246822519u; }
__attribute__((noinline)) static uint32_t b3(uint32_t x) { return c3(x + 0x9e37u) + (x << 3); }
__attribute__((noinline)) static uint32_t chain3(uint32_t x) { return b3(x) ^ c3(x >> 1); }

__attribute__((noinline)) static uint64_t varshift(uint64_t x, unsigned s) {
    unsigned k = s & 63u;
    int64_t sx = (int64_t)x;
    return (x << k) ^ (x >> k) ^ (uint64_t)(sx >> k);
}

__attribute__((noinline)) static uint64_t fmath(uint32_t u, uint32_t v) {
    float  f = (float)(u % 100000u) * 0.5f + 1.0f;
    double d = (double)(v % 100000u) / 3.0 + 1.0;
    float  g = f * 1.5f - 0.25f;
    double e = d * d - d;
    uint64_t r = 0;
    if (g > f) r ^= 0x11;
    if (e >= d) r ^= 0x22;
    // bit-exact round-trip through the integer lane (how the VM holds floats)
    uint32_t fb; memcpy(&fb, &g, 4);
    uint64_t db; memcpy(&db, &e, 8);
    return r ^ (uint64_t)fb ^ db;
}

__attribute__((noinline)) static uint64_t fconv(uint64_t x) {
    int32_t  i = (int32_t)(x & 0xffff);
    double   d = (double)i * 1.25 + 2.0;    // SITOFP
    int64_t  j = (int64_t)d;                // FPTOSI
    float    f = (float)d;                  // FPTRUNC (f64->f32)
    double   e = (double)f;                 // FPEXT  (f32->f64)
    uint64_t eb; memcpy(&eb, &e, 8);
    return (uint64_t)j ^ eb;
}

__attribute__((noinline)) static uint32_t sel_chain(uint32_t x) {
    uint32_t r = x;
    r = (r & 1u) ? r * 3u + 1u : r >> 1;
    r = (r > 1000u) ? r - 1000u : r + 7u;
    r = (r & 8u) ? (r ^ 0xa5a5u) : (r + 0x1234u);
    return r;
}

uint64_t compute(const uint8_t *data, size_t len) {
    uint64_t acc = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        uint64_t x = acc ^ ((uint64_t)data[i] + i * 0x100000001b3ULL);
        acc ^= sdiv_rem((int64_t)x, (int64_t)(x >> 7));
        acc += recur((uint32_t)(x % 25u), (uint32_t)x);
        acc ^= chain3((uint32_t)x);
        acc += varshift(x, (unsigned)(x >> 3));
        acc ^= fmath((uint32_t)x, (uint32_t)(x >> 32));
        acc += fconv(x);
        acc ^= sel_chain((uint32_t)acc);
    }
    return acc;
}
