// libFuzzer differential driver for RustCloak `virt`: baseline `compute` is linked in; the
// virtualized `compute` is dlopen'd from ./libvmobf.so. Every input is fed to both; any divergence
// aborts with the reproducing bytes printed. Coverage-guided, so libFuzzer drives the branch space
// of the (native) baseline, which is the same control flow the VM reproduces.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

extern uint64_t compute(const uint8_t *, size_t);     // baseline, linked
typedef uint64_t (*fn_t)(const uint8_t *, size_t);
static fn_t obf;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    void *h = dlopen("./libvmobf.so", RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); exit(1); }
    obf = (fn_t)dlsym(h, "compute");
    if (!obf) { fprintf(stderr, "dlsym compute failed\n"); exit(1); }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint64_t a = compute(data, size);
    uint64_t b = obf(data, size);
    if (a != b) {
        fprintf(stderr, "DIVERGENCE size=%zu baseline=%016llx virt=%016llx\n",
                size, (unsigned long long)a, (unsigned long long)b);
        abort();
    }
    return 0;
}
