#include <stdio.h>
int main() {
    FILE *f = fopen("/tmp/fsize_test", "w");
    if(f == NULL) {
        return 1;
    }
    int i;
    for(i = 0;i < 10000; i++) {
        if (fprintf(f, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") <= 0) {
            return 2;
        }
    }
    fclose(f);
    return 0;
}