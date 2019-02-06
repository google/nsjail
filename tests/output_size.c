#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[]) {
    FILE *f;
    if (strcmp(argv[1], "stdout") == 0)
        f = stdout;
    else f = fopen(argv[1], "w");
    if(f == NULL) {
        return 42;
    }
    int i;
    for(i = 0;i < 20000; i++) {
        if (fprintf(f, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") <= 0) {
            return 2;
        }
    }
    fclose(f);
    return 0;
}