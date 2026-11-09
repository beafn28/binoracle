/* Indirect-call hijack: a linear stack overflow overwrites a LOCAL function pointer that is
   then CALLED directly (`fp();`) -- a different primitive from ret2win's return-address
   overwrite (that one hijacks control at `ret`; this one hijacks it at an indirect `call`,
   mid-function, well before any `ret` executes). No canary, no PIE, NX on. AUTHORIZED local
   practice only. */
#include <stdio.h>
#include <stdlib.h>

void win(){ printf("[+] win reached\n"); system("/bin/sh"); }
void benign(){ printf("benign\n"); }

int main(){
    char buf[64];
    void (*fp)(void) = benign;
    printf("name? "); fflush(stdout);
    gets(buf);
    fp();
    return 0;
}
