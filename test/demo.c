// A small program with real control flow (a loop + a parity branch) that decodes a
// secret string, so we can check that flattening preserves behaviour and that a
// deflattener can recover the state machine.
#include <stdio.h>
#include <string.h>

static const unsigned char KEY[4] = {0x5a, 0x31, 0x7e, 0x14};

__attribute__((noinline))
void decode(char *out, const unsigned char *ct, int len) {
    for (int i = 0; i < len; i++)
        out[i] = (char)(ct[i] ^ KEY[i % 4]);
    if (len & 1)
        out[len - 1] = (char)(out[len - 1] ^ 0x20);
    out[len] = 0;
}

int main(void) {
    const char *p = "rustcloak::flatten-demo::ok";
    int n = (int)strlen(p);
    unsigned char ct[64];
    for (int i = 0; i < n; i++) ct[i] = (unsigned char)p[i] ^ KEY[i % 4];
    char out[64];
    decode(out, ct, n);
    printf("%s\n", out);
    return 0;
}
