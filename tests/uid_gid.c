#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    printf("uid %d\ngid %d\n", getuid(), getgid());
    system("/usr/bin/id");
    return 0;
}