#include <stdio.h>
#include <string.h>

int main()
{
    fprintf(stderr, "stderr\n");
    fprintf(stdout, "--------------\n");
    fprintf(stdout, "stdout\n");
    fprintf(stderr, "+++++++++++++++\n");
    return 0;
}