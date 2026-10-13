/* Stack overflow WITH a stack canary AND a format-string leak primitive -- the most common
   real-world canary-leak shape in CTF. Stage 1: printf(user_input) leaks stack slots, among them
   the canary (a random 64-bit value whose low byte is 0x00). Stage 2: a second read overflows
   past the (now recovered) canary to reach win(). NX on, canary ON, no PIE. AUTHORIZED / CTF. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }

void vuln(){
    char buf[256];
    printf("fmt> "); fflush(stdout);
    int n = read(0, buf, 200);     /* stage 1: a format string (fits in buf, does NOT reach canary) */
    if (n > 0) buf[n] = 0;
    printf(buf);                    /* format-string leak: %N$p reaches the intact stack canary */
    printf("\n"); fflush(stdout);
    printf("overflow> "); fflush(stdout);
    read(0, buf, 512);             /* stage 2: real overflow past the known canary -> win() */
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
