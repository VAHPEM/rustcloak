#include <stdio.h>
#include <stdint.h>
#include <string.h>
// Wholly float-eligible: exercises fadd/fsub/fmul/fdiv, ordered fcmp, fpext/fptrunc, fptosi/sitofp,
// fneg and fp constants, so virt virtualizes it whole. Prints the result's exact bit pattern so a
// single-ULP divergence between baseline and the VM is caught.
__attribute__((noinline)) double fcompute(double a, double b, float c, int n) {
    double acc = a;
    for (int i = 0; i < n; i++) {
        acc = acc * 1.000001 + b;          // fmul, fadd, fp const
        if (acc > 1e6)  acc = acc - 5e5;   // fcmp ogt, fsub
        if (acc < -1e6) acc = acc + 5e5;   // fcmp olt, fadd
        acc += (double)c;                  // fpext f32->f64
        acc = acc / 3.0;                   // fdiv
    }
    int k = (int)acc;                      // fptosi f64->i32
    acc += (double)k;                      // sitofp i32->f64
    float f = (float)acc;                  // fptrunc f64->f32
    acc = (double)f;                       // fpext f32->f64
    return -acc;                           // fneg
}
int main(void) {
    double r = fcompute(3.5, 0.25, 2.5f, 20);
    uint64_t bits;
    memcpy(&bits, &r, 8);
    printf("f=%016llx\n", (unsigned long long)bits);
    return 0;
}
