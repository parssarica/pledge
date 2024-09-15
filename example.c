#include <stdio.h>
#include <unistd.h>
#include "pledge.h"

int main(void)
{
    pledge("stdio wpath", NULL); // Pledges the code for only allowing stdio and wpath systemcalls.
    FILE* fd = fopen("example.txt", "r"); // fopen uses openat systemcall, which is in wpath.
    char content[256];
    fgets(content, 256, fd);
    printf("%s\n", content);
    execl("/bin/sh", NULL); // A backdoor! But execl is not included in either stdio or wpath. So seccomp kills the process and saved the day.

    return 0;
}
