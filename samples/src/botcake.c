/* House-of-botcake practice target (x86-64, real glibc tcache). A small menu heap (alloc/free/edit)
   plus a hijackable function pointer. House-of-botcake bypasses the tcache double-free key check by
   routing a double-free through the unsorted bin (consolidation) to obtain OVERLAPPING chunks, then
   tcache-poisons the overlapped chunk's fd to allocate over the function pointer -> write -> shell.
   NX on, no PIE (the function pointer is at a fixed address; the sandbox runs with ASLR off so heap
   addresses are deterministic). Intentionally vulnerable, AUTHORIZED local practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define N 32
char *chunks[N];
int nalloc = 0;

void win(void){ system("/bin/sh"); }
void (*handler)(void) __attribute__((aligned(16))) = 0;   /* hijack target */

static void rd(void *p, int n){ int g = 0; while (g < n){ int r = read(0, (char*)p + g, n - g); if (r <= 0) _exit(0); g += r; } }

int main(void){
    setvbuf(stdout, 0, _IONBF, 0);
    for (;;){
        unsigned char cmd;
        if (read(0, &cmd, 1) != 1) break;
        if (cmd == 1){ unsigned long sz; rd(&sz, 8); chunks[nalloc++] = malloc(sz); }
        else if (cmd == 2){ unsigned char i; rd(&i, 1); free(chunks[i]); }
        else if (cmd == 3){ unsigned char i; unsigned short len; rd(&i, 1); rd(&len, 2); rd(chunks[i], len); }
        else if (cmd == 4){ if (handler) handler(); }
        else break;
    }
    return 0;
}
