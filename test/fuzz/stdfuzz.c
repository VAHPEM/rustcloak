#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
extern uint64_t compute(const uint8_t*, size_t);     // baseline, linked
typedef uint64_t (*fn_t)(const uint8_t*, size_t);
static uint64_t st = 0x9e3779b97f4a7c15ULL;
static uint64_t xr(void){ st^=st<<13; st^=st>>7; st^=st<<17; return st; }
int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 5000000;
    void *ho = dlopen("./libobf.so", RTLD_NOW), *hl = dlopen("./liblazy.so", RTLD_NOW);
    if(!ho||!hl){ fprintf(stderr,"dlopen: %s\n", dlerror()); return 2; }
    fn_t obf=(fn_t)dlsym(ho,"compute"), lazy=(fn_t)dlsym(hl,"compute");
    uint8_t buf[512];
    for (long t = 0; t < iters; t++) {
        size_t len = (size_t)(xr() % 513);
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(xr() & 0xff);
        uint64_t a=compute(buf,len), b=obf(buf,len), c=lazy(buf,len);
        if (a!=b || a!=c) {
            printf("DIVERGENCE iter=%ld len=%zu base=%llx obf=%llx lazy=%llx\n",
                   t, len, (unsigned long long)a,(unsigned long long)b,(unsigned long long)c);
            return 1;
        }
    }
    printf("OK: %ld iters, baseline == eager == lazy (no divergence)\n", iters);
    return 0;
}
