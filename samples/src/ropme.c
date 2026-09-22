/* static, ROP-friendly: overflow + guaranteed /bin/sh string for ret2syscall demos. */
#include <unistd.h>
char binsh[] = "/bin/sh";
void vuln(){ char buf[64]; read(0, buf, 512); }   /* overflow */
int main(){ vuln(); return 0; }
