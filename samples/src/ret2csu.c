/* ret2csu practice target (x86-64): gadget-poor, so the two universal __libc_csu_init-style
   gadgets are the way to control rdi/rsi/rdx and make an indirect call. win() checks three
   argument sentinels and spawns a shell -- proving the chain set edi=r13d, rsi=r14, rdx=r15 and
   called through [r12+rbx*8]. A "/bin/sh" string is present for system(). Intentionally
   vulnerable, for AUTHORIZED local practice only. */
#include <stdlib.h>
#include <unistd.h>

void win(unsigned long a, unsigned long b, unsigned long c){
    /* a comes through edi (32-bit via `mov edi, r13d`), so it must fit in 32 bits */
    if (a == 0x1337 && b == 0xdead && c == 0xbeef)
        system("/bin/sh");
}

void *fnptr = win;            /* known indirect-call target in .data: `call [r12+rbx*8]` */

/* the two universal gadgets, laid out exactly like __libc_csu_init's tail */
__attribute__((naked, used)) void gadget_block(void){
    __asm__ volatile(
        "pop %rbx\n pop %rbp\n pop %r12\n pop %r13\n pop %r14\n pop %r15\n ret\n"   /* gadget1 */
        "mov %r15, %rdx\n mov %r14, %rsi\n mov %r13d, %edi\n"
        "call *(%r12,%rbx,8)\n ret\n"                                              /* gadget2 */
    );
}

void vuln(void){
    char buf[64];
    read(0, buf, 512);        /* overflow: 512 into 64 */
}

int main(void){
    write(1, "csu\n", 4);
    vuln();
    write(1, "done\n", 5);
    return 0;
}
