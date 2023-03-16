#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>

#define MAGIC_MAP_SIZE 0x2000
#define MAGIC_STACK_SIZE 0x4000

int sockfd = -1;

void testIPC() {
    struct msghdr msg = { 0 };

    char dummy[1];
    struct iovec io = { .iov_base = dummy, .iov_len = sizeof(dummy) };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char buf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if(recvmsg(sockfd, &msg, 0) < 0) {
        perror("recvmsg");
        return;
    }

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

    int fd = *(int*)CMSG_DATA(cmsg);
    printf("Injected fd: %d\n", fd);

    char* test = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("Message: \"%s\"\n", test);
}

void* thread_start(void* dummy) {
    testIPC();
    while(1) {
        printf("PThread works!\n");
        usleep(500000);
    }
}

bool cleanup() {
    void* magic;
    void* stack;

    if(read(sockfd, &magic, sizeof(magic)) < 0) {
        perror("read");
        return false;
    }

    if(read(sockfd, &stack, sizeof(stack)) < 0) {
        perror("read");
        return false;
    }

    if(munmap(magic, MAGIC_MAP_SIZE) < 0) {
        perror("munmap");
        return false;
    }

    stack -= MAGIC_STACK_SIZE;
    if(munmap(stack, MAGIC_STACK_SIZE) < 0) {
        perror("munmap");
        return false;
    }

    return true;
}

int main() {
    sockfd = getauxval(AT_IGNORE);
    if(sockfd <= 0) {
        printf("Loader did not provide a socket fd\n");
        return 1;
    }

    if(!cleanup()) {
        printf("Cleanup failed\n");
        return 1;
    }

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_create(&tid, &attr, thread_start, NULL);
    pthread_exit(0);
}