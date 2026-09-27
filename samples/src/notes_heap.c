/* Classic menu-driven heap "notes" challenge: create/edit/free/show fixed-size notes with a
   dangling-pointer bug (free does not clear the slot), enabling tcache/UAF exploitation and a libc
   leak via a freed unsorted-bin chunk. NX on, no PIE. AUTHORIZED practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define N 8
static char *notes[N];
static unsigned sizes[N];

static int rd(const char *p){ char b[16]; printf("%s", p); fflush(stdout);
    if (read(0, b, 15) <= 0) exit(0); return atoi(b); }

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    for (;;){
        int op = rd("1)new 2)edit 3)free 4)show >");
        int i = rd("idx>");
        if (i < 0 || i >= N) continue;
        if (op == 1){ int s = rd("size>"); if (s <= 0 || s > 0x500) continue;
            notes[i] = malloc(s); sizes[i] = s;
            printf("data>"); fflush(stdout); read(0, notes[i], s); }
        else if (op == 2){ if (notes[i]){ printf("data>"); fflush(stdout);
            read(0, notes[i], sizes[i]); } }                 /* edit: no bounds beyond stored size */
        else if (op == 3){ free(notes[i]); }                 /* free: leaves dangling pointer -> UAF */
        else if (op == 4){ if (notes[i]) write(1, notes[i], sizes[i]); }  /* show: leaks freed data */
        else return 0;
    }
}
