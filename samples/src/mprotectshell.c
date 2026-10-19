/* NX bypass via mprotect(): stage shellcode into a known, page-aligned .bss buffer (fixed
   address, no leak needed -- static, no-PIE), then overflow a stack buffer with a ROP chain
   that calls mprotect(shellbuf, 0x1000, PROT_READ|WRITE|EXEC) and jumps into the now-executable
   buffer. Statically linked (mprotect() itself is callable, no raw syscall gadget needed) --
   but a plain "pop rdx; ret" never shows up by chance in this libc build, so (same craft as
   ret2csu.c's gadget_block) one is engineered in on purpose: realistic in spirit (real binaries
   often happen to have one), deterministic for the oracle's test fixture. AUTHORIZED practice
   only. */
#include <unistd.h>

__attribute__((naked, used)) void gadget_pop_rdx(void){
    __asm__ volatile("pop %rdx\n ret\n");
}

char shellbuf[0x1000] __attribute__((aligned(0x1000)));

void vuln() {
    char overflow_buf[64];
    read(0, shellbuf, sizeof(shellbuf));    /* stage 1: attacker-controlled shellcode */
    read(0, overflow_buf, 400);             /* stage 2: overflow -> ROP to mprotect + jump */
}

int main() {
    vuln();
    return 0;
}
