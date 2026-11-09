/* 32-bit SROP practice target: statically linked, NX on, no canary, no win/system.
   The overflow plus an explicit `int 0x80; ret` gadget makes SROP (sigreturn-oriented
   programming) the natural 32-bit path: set EAX=119 (sigreturn) and stage a fake sigcontext
   that performs execve("/bin/sh") via EAX=11 / EBX=&binsh / int 0x80. A "/bin/sh" string is
   embedded so the frame has a target. Intentionally vulnerable, for AUTHORIZED local practice. */
#include <unistd.h>

char binsh[] = "/bin/sh";               /* target string for the SROP frame */

/* explicit `int 0x80; ret` gadget so a static 32-bit binary has a clean syscall gate */
void syscall_gadget(){ asm volatile("int $0x80; ret"); }

void vuln(){
    char buf[64];
    read(0, buf, 512);                  /* overflow: 512 into 64 */
}

int main(){
    write(1, "srop32\n", 7);
    vuln();
    write(1, "done\n", 5);
    return 0;
}
