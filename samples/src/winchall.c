/* Windows PE practice target: strcpy overflow + gift function. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void win(){ printf("[+] win reached\n"); system("cmd.exe"); }
int main(){
    char buf[64];
    char in[256];
    printf("pass? "); fflush(stdout);
    if (fgets(in, sizeof in, stdin)) {
        strcpy(buf, in);                     /* overflow */
        if (strcmp(buf, "sup3rs3cr3t\n") == 0) win();  /* angr-solvable */
    }
    printf("bye\n");
    return 0;
}
