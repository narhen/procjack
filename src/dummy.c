#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char *argv[])
{
    char *hello = "Hello tracer!";
    printf("hello @ %p: %s\n", hello, hello);

    while (1) {
        printf(".");
        fflush(stdout);
        sleep(1);
    }

    return 0;
}
