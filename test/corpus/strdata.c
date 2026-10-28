// Corpus for strenc wide/data coverage (A2): a UTF-16-ish u16 string, a u32 data table, and a
// plain i8 string -- all private const arrays. strenc must encrypt all three and the program must
// still fold them to the same checksum as baseline (proof the non-i8 arrays decrypt correctly).
#include <stdio.h>
#include <stdint.h>

static const uint16_t wide[]  = {0x48,0x65,0x6c,0x6c,0x6f,0x2c,0x20,0x77,0x69,0x64,0x65,0};
static const uint32_t table[] = {0x9e3779b9u,0x85ebca6bu,0xc2b2ae35u,0x27d4eb2fu,0x165667b1u};
static const char     tag[]   = "strdata::secret::marker";

__attribute__((noinline)) static uint32_t fold(void) {
    uint32_t h = 2166136261u;
    for (int i = 0; wide[i]; i++)   h = (h ^ wide[i]) * 16777619u;
    for (int i = 0; i < 5; i++)     h = (h ^ table[i]) * 16777619u;
    for (const char *p = tag; *p; p++) h = (h ^ (uint8_t)*p) * 16777619u;
    return h;
}

int main(void) {
    printf("strdata=%08x\n", fold());
    return 0;
}
