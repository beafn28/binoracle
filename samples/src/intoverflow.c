/* Integer overflow leading to an undersized allocation and a heap overflow: a signed length is
   checked against a max but a negative/large value wraps, so the copy writes past the buffer.
   NX on, no PIE. AUTHORIZED practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(){ system("/bin/sh"); }

void vuln(){
    short len;                      /* signed 16-bit: wraps */
    printf("len: "); fflush(stdout);
    if (scanf("%hd", &len) != 1) return;
    if (len > 256) { puts("too big"); return; }   /* check bypassed by negative len */
    char *buf = malloc(64);
    read(0, buf, (unsigned)len);   /* len sign-extends to a huge size_t -> heap overflow */
    (void)buf;
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
