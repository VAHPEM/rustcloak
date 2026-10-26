// Differential-fuzzing target for RustCloak's `virt` (code virtualization) transform.
//
// Every helper here is deliberately *eligible* for virtualization and exercises one lowering path
// that the VM must get exactly right -- the same paths that regressed in the constant-pool bugs:
//   trunc_mix   trunc i64 -> i8/i16/i32          (width-mask constant pool)
//   struct_sum  struct-field loads               (GEP folded constant offsets 0/8/16/18)
//   arr_pick    constant array indices           (GEP folded constant offsets 0/12/28)
//   decode      byte buffer load/store + i&3 GEP  (variable-index GEP, mixed widths)
//   caller      calls a uint16_t-returning fn     (narrow CALL return re-zero-extension)
//   mix         32-bit arithmetic                 (width-sensitive arithmetic/compare)
//
// `compute()` folds all of them -- and every output buffer -- into one u64, so a single scalar
// comparison in the driver detects any divergence in a return value OR a written buffer. The
// baseline (no plugin) and the virtualized build (RUSTCLOAK_VM=1) must return the same u64 for
// every input. See vm_driver.c / vm_stdfuzz.c and difffuzz_vm.sh.
#include <stdint.h>
#include <stddef.h>

struct S { uint32_t a; uint64_t b; uint16_t c; uint8_t d; };

__attribute__((noinline)) static uint64_t trunc_mix(uint64_t x) {
    uint8_t  a = (uint8_t)x;
    uint16_t b = (uint16_t)(x >> 8);
    uint32_t c = (uint32_t)(x >> 16);
    return (uint64_t)a + ((uint64_t)b << 7) + ((uint64_t)c << 20) + (x & 0xffu);
}

__attribute__((noinline)) static uint64_t struct_sum(struct S *s) {
    return (uint64_t)s->a + s->b + (uint64_t)s->c + (uint64_t)s->d;
}

__attribute__((noinline)) static uint32_t arr_pick(const uint32_t *p) {
    return p[0] + p[3] + p[7];
}

__attribute__((noinline)) static void decode(uint8_t *out, const uint8_t *ct, int len,
                                             const uint8_t *key) {
    for (int i = 0; i < len; i++)
        out[i] = (uint8_t)(ct[i] ^ key[i & 3]);
}

// returns a narrow int: exercises the CALL handler re-zero-extending a value whose ABI high bits
// are undefined.
__attribute__((noinline)) static uint16_t narrow_ret(uint32_t x) {
    return (uint16_t)((x * 2654435761u) >> 11);
}
__attribute__((noinline)) static uint32_t caller(uint32_t x, uint32_t y) {
    return (uint32_t)narrow_ret(x) + (uint32_t)narrow_ret(y) * 3u;
}

__attribute__((noinline)) static uint32_t mix(uint32_t x, uint32_t y) {
    uint32_t a = (x ^ 0x9e3779b9u) + (y << 7);
    uint32_t b = (a * 0x85ebca6bu) ^ (a >> 13);
    return (b - (x | 0x1234u)) & 0xffffu;
}

uint64_t compute(const uint8_t *data, size_t len) {
    uint64_t acc = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        uint64_t x = acc ^ ((uint64_t)data[i] + i * 0x100000001b3ULL);
        acc ^= trunc_mix(x);
        struct S s = { (uint32_t)x, x * 3 + 1, (uint16_t)(x >> 5), (uint8_t)(x >> 11) };
        acc += struct_sum(&s);
        uint32_t p[8];
        for (int j = 0; j < 8; j++) p[j] = (uint32_t)(x >> j) + j;
        acc ^= arr_pick(p);
        uint8_t buf[16], out[16], key[4];
        for (int j = 0; j < 16; j++) buf[j] = (uint8_t)(x >> (j & 7)) + j;
        for (int j = 0; j < 4;  j++) key[j] = data[(i + (size_t)j) % len];
        decode(out, buf, 16, key);
        for (int j = 0; j < 16; j++) acc = acc * 65599u + out[j];
        acc += caller((uint32_t)x, (uint32_t)(x >> 32));
        acc ^= mix((uint32_t)acc, (uint32_t)(acc >> 32));
    }
    return acc;
}
