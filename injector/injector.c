#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/user.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sched.h>

#define SC_PATH "shellcode.bin"
#define MAGIC_PATH "magic.bin"
#define PAYLOAD_PATH "payload"

#define SOCKFD 1023

void sighandler(int sig) {
    if(sig != SIGCHLD)
        return;

    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if(pid <= 0)
        return;
    printf("Pid %d exited with %d\n", pid, WSTOPSIG(status));
    kill(pid, SIGKILL);
    exit(0);
}

pid_t spawn(const char* path, int* socks) {
    pid_t pid = fork();
    if(pid)
        return pid;

    dup2(socks[1], SOCKFD);
    close(socks[0]);
    close(socks[1]);
    
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

    execl(path, path, NULL);

    return -1;
}

size_t loadShellcode(void** sc) {
    FILE* f = fopen(SC_PATH, "r");
    if(!f)
        return 0;
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* mem = malloc(sz);
    fread(mem, 1, sz, f);
    fclose(f);
    *sc = mem;
    return sz;
}

ssize_t writeStr(int fd, const char* str) {
    return write(fd, str, strlen(str));
}

void waitAck(int fd) {
    char dummy;
    read(fd, &dummy, sizeof(dummy));
}

void* readRemoteMem(pid_t pid, unsigned long long address, size_t sz) {
    long* buf = malloc(sz);
    for(int i = 0; i < sz / sizeof(long); i++) {
        buf[i] = ptrace(PTRACE_PEEKDATA, pid, address + i * sizeof(long), NULL);
    }
    return buf;
}

void writeRemoteMem(pid_t pid, unsigned long long address, void* buf, size_t sz) {
    long* tmp = (long*)buf;
    for(int i = 0; i < sz / sizeof(long); i++) {
        ptrace(PTRACE_POKEDATA, pid, address + i * sizeof(long), tmp[i]);
    }
}

void* injectMemFd(int sockfd) {
    int fd = memfd_create("shmem", 0);
    ftruncate(fd, 0x1000);

    void* ptr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(!ptr)
        return NULL;

    struct msghdr msg = { 0 };
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));
    struct iovec io = { .iov_base = "A", .iov_len = 1 };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    *(int*)CMSG_DATA(cmsg) = fd;

    sendmsg(sockfd, &msg, 0);

    return ptr;
}

int main() {
    signal(SIGCHLD, sighandler);

    int magicfd = open(MAGIC_PATH, O_RDONLY);
    if(magicfd < 0) {
        printf("No magic :(\n");
        return 1;
    }

    int socks[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) {
        printf("No sockets\n");
        return 1;
    }
    
    pid_t pid = spawn("target", socks);
    close(magicfd);
    close(socks[1]);
    printf("PID: %d\n", pid);

    int status;
    waitpid(pid, &status, 0);
    if(WSTOPSIG(status) != SIGTRAP) {
        printf("Something not right\n");
        return 1;
    }

    struct user_regs_struct regs;
    struct user_regs_struct savedRegs;

    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, 1, &io);
    memcpy(&savedRegs, &regs, sizeof(regs));

    regs.r8 = magicfd;
    regs.r12 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN;
    regs.r13 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_IO;
    regs.r14 = SOCKFD;
    ptrace(PTRACE_SETREGSET, pid, 1, &io);

    void* sc;
    size_t scsz = loadShellcode(&sc);
    if(!scsz) {
        printf("No shellcode :(\n");
        return 1;
    }

    size_t sz = (scsz / sizeof(long) + 1) * sizeof(long);

    void* origMem = readRemoteMem(pid, savedRegs.rip, sz);
    void* newMem = malloc(sz);
    memcpy(newMem, origMem, sz);
    memcpy(newMem, sc, scsz);
    writeRemoteMem(pid, savedRegs.rip, newMem, sz);

    printf("Starting the shellcode...\n");
    ptrace(PTRACE_CONT, pid, NULL, 0);

    waitpid(pid, &status, 0);
    if(WSTOPSIG(status) != SIGTRAP) {
        printf("Something not right 2\n");
        return 1;
    }

    ptrace(PTRACE_GETREGSET, pid, 1, &io);
    int tid = regs.rax;
    printf("TID: %d\n", tid);

    writeStr(socks[0], PAYLOAD_PATH);
    waitAck(socks[0]);
    
    write(socks[0], &regs.rbx, sizeof(unsigned long long));
    write(socks[0], &regs.rsi, sizeof(unsigned long long));

    writeRemoteMem(pid, savedRegs.rip, origMem, sz);

    io.iov_base = &savedRegs;
    ptrace(PTRACE_SETREGSET, pid, 1, &io);

    ptrace(PTRACE_CONT, pid, NULL, 0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    char* test = injectMemFd(socks[0]);
    strcpy(test, "Hello, world!");

    close(socks[0]);
    free(origMem);
    free(newMem);

    while(1)
        usleep(100000);
    
    return 0;
}