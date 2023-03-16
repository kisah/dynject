#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>

int main() {
    while(1) {
        printf("This is static\n");
        usleep(500000);
    }
    return 0;
}