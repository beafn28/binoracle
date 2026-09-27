/* Stack overflow WITH stack canary + a leak primitive: the intended path is to leak the canary
   (via the echo that prints the buffer) and then overflow past it to reach win().
   NX on, canary ON, no PIE. AUTHORIZED practice only. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }

void vuln(){
    char buf[64];
    printf("name: "); fflush(stdout);
    read(0, buf, 72);              /* first read: fill up to and into the canary's low bytes */
    printf("hi %s\n", buf);        /* leak: prints buf (and trailing canary if no NUL) */
    printf("again: "); fflush(stdout);
    read(0, buf, 200);            /* second read: real overflow past the (now known) canary */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
