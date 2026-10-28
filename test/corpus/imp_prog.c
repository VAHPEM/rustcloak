#include <stdio.h>
#include <stdlib.h>
// getenv is the API to hide. With RC_NOPE_XYZ unset it returns NULL, so the output is deterministic.
int main(void) {
    char *p = getenv("RC_NOPE_XYZ");
    printf("imp=%d\n", p ? 1 : 0);
    return 0;
}
