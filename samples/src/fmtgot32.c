/* 32-bit format-string with a GOT-overwrite target: the user string is passed straight to printf,
   giving arbitrary write (%n). Intended path: overwrite printf@GOT with system, then printf("/bin/sh")
   becomes system("/bin/sh"). NX on, no PIE (GOT at a fixed address), Partial RELRO. x86-32 cdecl.
   AUTHORIZED practice only. */
#include <stdio.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }

void vuln(){
    char buf[128];
    printf("say: "); fflush(stdout);
    read(0, buf, sizeof(buf) - 1);
    printf(buf);                   /* uncontrolled format string */
    printf("\n");
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    for (int i = 0; i < 6; i++) vuln();   /* several rounds: leak then write */
    return 0;
}
