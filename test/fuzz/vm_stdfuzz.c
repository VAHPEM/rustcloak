// Standalone differential driver for RustCloak `virt` when no libFuzzer runtime is present:
// xorshift-random inputs fed to baseline `compute` (linked) and the virtualized `compute`
// (./libvmobf.so). Deterministic from a fixed PRNG seed, so a divergence reproduces exactly.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

extern uint64_t compute(const uint8_t *, size_t);
typedef uint64_t (*fn_t)(const uint8_t *, size_t);

static uint64_t st = 0x9e3779b97f4a7c15ULL;
static uint64_t xr(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 5000000;
    void *h = dlopen("./libvmobf.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    fn_t obf = (fn_t)dlsym(h, "compute");
    if (!obf) { fprintf(stderr, "dlsym compute failed\n"); return 2; }
    uint8_t buf[512];
    for (long t = 0; t < iters; t++) {
        size_t len = (size_t)(xr() % 513);
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(xr() & 0xff);
        uint64_t a = compute(buf, len), b = obf(buf, len);
        if (a != b) {
            printf("DIVERGENCE iter=%ld len=%zu baseline=%016llx virt=%016llx\n",
                   t, len, (unsigned long long)a, (unsigned long long)b);
            return 1;
        }
    }
    printf("OK: %ld iters, baseline == virt (no divergence)\n", iters);
    return 0;
}
