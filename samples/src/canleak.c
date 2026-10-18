/* Stack overflow WITH a stack canary AND a genuine leak primitive -- the leakable sibling of
   canary.c. The intended path: the first read is long enough to overwrite the canary's null
   least-significant byte, so the following `%s` echo keeps going and prints the upper 7 canary
   bytes; recover canary = 0x00|leaked7, then the second read overflows past the (now known)
   canary to reach win(). NX on, canary ON, no PIE. AUTHORIZED / CTF practice only. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }

void vuln(){
    char buf[64];
    printf("name: "); fflush(stdout);
    read(0, buf, 96);              /* long enough to reach and overwrite the canary's LSB */
    printf("hi %s\n", buf);        /* leak: %s runs past the overwritten LSB into the canary */
    printf("again: "); fflush(stdout);
    read(0, buf, 256);            /* real overflow past the (now known) canary -> win() */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
