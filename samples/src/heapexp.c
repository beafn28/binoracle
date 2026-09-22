/* heap exploitation practice: menu-driven UAF (no clear on free) -> tcache poisoning.
   Has a win() (no libc leak needed: overwrite free@GOT with win). no-PIE, partial RELRO. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *chunks[16];
void win(){ printf("[+] win reached\n"); system("/bin/sh"); }
static int rd(){ char b[16]; if(!fgets(b,sizeof b,stdin)) exit(0); return atoi(b); }
int main(){
    setvbuf(stdout,0,_IONBF,0); setvbuf(stdin,0,_IONBF,0);
    while(1){
        printf("1)new 2)free 3)edit 4)show\n> ");
        int c=rd();
        if(c==1){ int i=rd(); chunks[i]=malloc(0x20); }
        else if(c==2){ int i=rd(); free(chunks[i]); }        /* UAF: pointer not cleared */
        else if(c==3){ int i=rd(); read(0, chunks[i], 0x20); }/* write into (freed) chunk */
        else if(c==4){ int i=rd(); write(1, chunks[i], 8); } /* leak */
        else break;
    }
    return 0;
}
