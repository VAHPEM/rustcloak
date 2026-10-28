// Freestanding driver for the arch/format matrix: no libc. Calls the exported vm_free_elf.c
// functions over fixed inputs, folds the results to one byte, and returns it via the raw exit
// syscall -- so a static, -nostdlib binary runs on bare aarch64 and (under qemu-user) x86-64 with
// no sysroot. The baseline and the RustCloak-obfuscated build must exit with the same code.
typedef unsigned int u32;
typedef unsigned long long u64;

u32 mix(u32, u32);
u64 fold64(u64, u64);
u32 crc_ish(u32, u32);

static u64 compute(void) {
    u64 a = 1469598103934665603ULL;
    for (u32 i = 0; i < 2000u; i++) {
        a ^= mix(i * 2654435761u, i ^ 0x5a5au);
        a += fold64(a, (u64)i << 13);
        a ^= crc_ish((u32)a, i % 100u);
    }
    return a;
}

static void sys_exit(int code) {
#if defined(__x86_64__)
    __asm__ volatile("movl %0, %%edi\n\tmovl $60, %%eax\n\tsyscall" : : "r"(code) : "eax", "edi");
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = code;
    register long x8 __asm__("x8") = 93;   // __NR_exit
    __asm__ volatile("svc 0" : : "r"(x0), "r"(x8));
#endif
    __builtin_unreachable();
}

void _start(void) {
    sys_exit((int)(compute() & 0xffull));
}
