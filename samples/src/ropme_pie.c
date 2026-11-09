/* ROP on PIE: stack overflow, NX, PIE, no gift function. Built -static-pie so the binary
 * itself carries syscall gadgets and a "/bin/sh" string, making an execve-syscall ROP chain
 * (with addresses rebased onto the resolved PIE base) the intended path. Authorized practice. */
#include <stdio.h>
#include <unistd.h>

char shellstr[] = "/bin/sh";

void vuln(void){
    char buf[64];
    printf("data: "); fflush(stdout);
    read(0, buf, 512);        /* overflow: 512 into 64 */
}

int main(void){
    setvbuf(stdout, 0, 2, 0);
    vuln();
    return 0;
}
