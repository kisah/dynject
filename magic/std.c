#include <syscall.h>
#include "std.h"

long syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(number),
          "D"(a1),
          "S"(a2),
          "d"(a3),
          "r"(r10),
          "r"(r8),
          "r"(r9)
        : "memory",
          "rcx",
          "r11"
    );
    return ret;
}

int open(const char* path, int flags) {
    return syscall(__NR_open, (long)path, flags, 0, 0, 0, 0);
}

int read(int fd, void* buf, int len) {
    return syscall(__NR_read, fd, (long)buf, len, 0, 0, 0);
}

int write(int fd, void* buf, int len) {
    return syscall(__NR_write, fd, (long)buf, len, 0, 0, 0);
}

int close(int fd) {
    return syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

void exit(int code) {
    syscall(__NR_exit, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    long ret = syscall(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
    if(ret < 0)
        return MAP_FAILED;
    return (void*)ret;
}

int munmap(void* addr, size_t length) {
    return syscall(__NR_munmap, (long)addr, length, 0, 0, 0, 0);
}

int strlen(char* str) {
    int n = 0;
    while(*str++)
        n++;
    return n;
}

void puts(char* str) {
    int len = strlen(str);
    write(1, str, len);
}

off_t lseek(int fildes, off_t offset, int whence) {
    return syscall(__NR_lseek, fildes, offset, whence, 0, 0, 0);
}

ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    lseek(fd, offset, 0);
    ssize_t sz = (ssize_t)read(fd, buf, count);
    return sz;
}

void* malloc(size_t size) {
    size = (size & ~0xfff) + 0x2000;
    void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if(ptr == MAP_FAILED)
        return MAP_FAILED;
    *(size_t*)ptr = size;
    return ptr + sizeof(size_t);
}

void free(void* ptr) {
    void* realptr = ptr - sizeof(size_t);
    size_t size = *(size_t*)realptr;
    munmap(realptr, size);
}

int mprotect(const void* addr, size_t len, int prot) {
    return syscall(__NR_mprotect, (long)addr, len, prot, 0, 0, 0);
}

void memset(void* s, int c, size_t n) {
    char* m = s;
    while(n--)
        *m++ = (char)c;
}

int memcmp(void* m1, void* m2, int n) {
    char* a = (char*)m1;
    char* b = (char*)m2;
    while(n--)
        if(*a++ != *b++)
            return 1;
    return 0;
}