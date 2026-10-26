// Portable differential driver for RustCloak `virt`, for the cross-architecture / cross-format
// matrix (test/matrix.sh). Unlike vm_driver.c / vm_stdfuzz.c -- which dlopen() the virtualized
// `compute` from a shared object (POSIX-only, and awkward under an emulator) -- this links BOTH
// computations statically into one self-contained binary and compares them internally:
//
//   compute_base  : vm_target.c compiled WITHOUT the plugin   (-Dcompute=compute_base)
//   compute_virt  : vm_target.c compiled WITH  RUSTCLOAK_VM=1  (-Dcompute=compute_virt)
//
// The result is a single static executable that runs unchanged on Linux x86-64, on Linux AArch64
// under qemu-aarch64, and as a Windows PE under wine -- no loader, no dlopen, no libFuzzer runtime.
// It drives xorshift-random inputs through both and aborts on the first divergence, so a mismatch
// reproduces exactly from the (fixed) PRNG seed and the iteration index.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern uint64_t compute_base(const uint8_t *, size_t);
extern uint64_t compute_virt(const uint8_t *, size_t);

static uint64_t st = 0x9e3779b97f4a7c15ULL;
static uint64_t xr(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 2000000;
    if (argc > 2) st = strtoull(argv[2], NULL, 0);      // optional PRNG seed override
    uint8_t buf[512];
    for (long t = 0; t < iters; t++) {
        size_t len = (size_t)(xr() % 513);
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(xr() & 0xff);
        uint64_t a = compute_base(buf, len), b = compute_virt(buf, len);
        if (a != b) {
            printf("DIVERGENCE iter=%ld len=%zu base=%016llx virt=%016llx\n",
                   t, len, (unsigned long long)a, (unsigned long long)b);
            return 1;
        }
    }
    printf("OK: %ld iters, base == virt (no divergence)\n", iters);
    return 0;
}
