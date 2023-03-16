#pragma once

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <elf.h>

#define _SYS_MMAN_H
#ifndef __USE_MISC
    #define __USE_MISC
#endif
#include <bits/mman.h>
#undef _SYS_MMAN_H

#define MAP_FAILED	((void *) -1)
#define O_RDONLY 0

#define perror puts

int open(const char* path, int flags);
int read(int fd, void* buf, int len);
int write(int fd, void* buf, int len);
int close(int fd);
void exit(int code);
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
void puts(char* str);
ssize_t pread(int fd, void* buf, size_t count, off_t offset);
void* malloc(size_t size);
void free(void* dummy);
int mprotect(const void* addr, size_t len, int prot);
void memset(void* s, int c, size_t n);
int memcmp(void* m1, void* m2, int n);