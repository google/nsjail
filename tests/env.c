#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("%s\n%s\n", getenv("env"), getenv("test"));
    return 0;
}