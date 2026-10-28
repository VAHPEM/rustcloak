#include <stdio.h>
int main(void) {
    long acc = 0;
    for (int i = 1; i <= 20; i++)
        acc += (long)i * 131 + 17;
    acc ^= 0x5a5a;
    acc = acc * 3 + 11;
    printf("at=%ld\n", acc);
    return 0;
}
