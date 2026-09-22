/* format-string: user input used directly as printf format. */
#include <stdio.h>
#include <string.h>
int main(){
    char buf[128];
    printf("say: "); fflush(stdout);
    if (fgets(buf, sizeof buf, stdin)) {
        printf(buf);        /* uncontrolled format string -> %p/%n */
        printf("\n");
    }
    return 0;
}
