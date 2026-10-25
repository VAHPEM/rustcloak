#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
extern uint64_t compute(const uint8_t*, size_t);
typedef uint64_t (*fn_t)(const uint8_t*, size_t);
static fn_t obf, lazy;
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    void *ho = dlopen("./libobf.so", RTLD_NOW|RTLD_LOCAL);
    void *hl = dlopen("./liblazy.so", RTLD_NOW|RTLD_LOCAL);
    if (!ho || !hl) { fprintf(stderr, "dlopen: %s\n", dlerror()); exit(1); }
    obf = (fn_t)dlsym(ho, "compute"); lazy = (fn_t)dlsym(hl, "compute");
    if (!obf || !lazy) { fprintf(stderr, "dlsym failed\n"); exit(1); }
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint64_t a = compute(data, size), b = obf(data, size), c = lazy(data, size);
    if (a != b || a != c) {
        fprintf(stderr, "DIVERGENCE size=%zu base=%llx obf=%llx lazy=%llx\n",
                size, (unsigned long long)a, (unsigned long long)b, (unsigned long long)c);
        abort();
    }
    return 0;
}
