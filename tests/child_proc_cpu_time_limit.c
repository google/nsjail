#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/types.h>

int main()
{
    int status;
    int pid;

    if ((pid = fork()) < 0) {
        perror("fork error");
        return 0;
    }

    if (pid == 0) {
        while (1) {};
    }
    else {
        struct rusage resource_usage;
        if (wait4(pid, &status, 0, &resource_usage) == -1) {
            perror("wait4 error!");
        }
    }

    return 0;
}