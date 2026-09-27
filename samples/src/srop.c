/* SROP practice target: statically linked, minimal, NX on, no canary, no win/system.
   The overflow plus an explicit `syscall; ret` gadget makes SROP (sigreturn-oriented
   programming) the natural path: set RAX=15 (rt_sigreturn) and stage a fake sigcontext
   to call execve("/bin/sh"). A "/bin/sh" string is embedded so the frame has a target.
   Intentionally vulnerable, for AUTHORIZED local practice only. */
#include <unistd.h>
#include <string.h>

char binsh[] = "/bin/sh";              /* target string for the SROP frame */

/* explicit `syscall; ret` gadget so a static binary without a clean one still has it */
void syscall_gadget(){ asm volatile("syscall; ret"); }

void vuln(){
    char buf[64];
    read(0, buf, 512);                 /* overflow: 512 into 64 */
}

int main(){
    const char *msg = "srop\n";
    write(1, msg, 5);
    vuln();
    write(1, "done\n", 5);
    return 0;
}
