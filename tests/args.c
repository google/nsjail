#include <stdio.h>

int main(int argc, char *argv[]) {
    int j;
    for (j = 0; j < argc; j++)
        printf("argv[%d]: %s\n", j, argv[j]);
    return 0;
}