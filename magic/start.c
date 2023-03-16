#include "std.h"

void main(int sockfd);

void _start(int sockfd) {
    main(sockfd);
    exit(1);
}