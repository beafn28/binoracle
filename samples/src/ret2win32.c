/* 32-bit ret2win: classic stack overflow on x86 (args passed on the stack).
   NX on, no canary, no PIE, dynamically linked. AUTHORIZED practice only. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }   /* target: call with a stack-passed arg layout */

void vuln(){
    char buf[64];
    printf("give: "); fflush(stdout);
    read(0, buf, 200);             /* overflow: 200 into 64 */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    puts("bye");
    return 0;
}
