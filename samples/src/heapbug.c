/* heap bug practice: double-free and heap overflow reachable from stdin.
   Input starting with 'f' triggers a double free; 'o' triggers a heap overflow. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){
    setvbuf(stdout, 0, _IONBF, 0);
    char cmd[32];
    char *a = malloc(64);
    char *b = malloc(64);
    if (!fgets(cmd, sizeof cmd, stdin)) return 0;
    free(a);
    if (cmd[0] == 'f') free(a);                 /* double free */
    if (cmd[0] == 'o') memcpy(b, cmd, 200);     /* heap overflow past 64 */
    free(b);
    puts("done");
    return 0;
}
