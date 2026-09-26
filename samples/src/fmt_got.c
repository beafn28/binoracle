/* Format-string with a GOT-overwrite target: the user string is passed straight to printf, giving
   arbitrary read/write (%n). Intended path: overwrite a GOT entry (e.g. printf/exit) with win().
   NX on, no PIE (so the GOT is at a fixed address). AUTHORIZED practice only. */
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
    for (int i = 0; i < 3; i++) vuln();   /* several rounds: leak then write */
    return 0;
}
