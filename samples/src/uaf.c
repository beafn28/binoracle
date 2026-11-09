/* Use-after-free with a function pointer in the freed object: allocate an object holding a fn
   pointer, free it, then reallocate a same-size buffer the attacker controls (tcache reuse) and
   trigger the stale call. Menu-driven, classic CTF shape. AUTHORIZED practice only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct obj { void (*action)(void); char name[24]; };

void hello(){ puts("hello"); }
void win(){ system("/bin/sh"); }        /* target for the hijacked function pointer */

static struct obj *o = 0;

static int menu(){
    printf("1)new 2)free 3)run 4)note >"); fflush(stdout);
    char b[8]; if (read(0, b, 7) <= 0) exit(0); return atoi(b);
}

int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    char line[64];
    for (;;){
        switch (menu()){
        case 1: o = malloc(sizeof(*o)); o->action = hello; break;   /* new */
        case 2: free(o); break;                                     /* free (no NULL) -> UAF */
        case 3: if (o) o->action(); break;                          /* use (maybe after free) */
        case 4:                                                      /* note: heap write of same size */
            printf("data: "); fflush(stdout);
            read(0, line, sizeof(line));
            void *p = malloc(sizeof(*o)); memcpy(p, line, sizeof(*o));  /* reclaims freed chunk */
            break;
        default: return 0;
        }
    }
}
