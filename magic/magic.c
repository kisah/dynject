/*
 * Copyright (C) 2017 Lubos Dolezel
 * Copyright (C) 2021-2023 kisah
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "std.h"
#include "auxvec.h"

#define ElfW(type)    _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)    e##w##t

#define MY_ELF_CLASS ELFCLASS64
#define __ELF_NATIVE_CLASS 64

#define ELF_MIN_ALIGN 0x1000
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define JUMPX(stack, addr) asm volatile("mov %1, %%rsp; jmpq *%0" :: "m"(addr), "r"(stack))

struct loader_context
{
    uintptr_t interp_entry;
    uintptr_t exec_entry;
    uintptr_t exec_phstart;
    uintptr_t exec_phentsize;
    uintptr_t exec_phnum;
    uintptr_t interp_base;
};

static void run(const char* path, int sockfd);
static void load(const char* path, struct loader_context* lc, bool isInterp);
static void loader_return(void);

void run(const char* path, int sockfd)
{
    struct loader_context lc = { 0 };
    unsigned long *stack, *stackmem;
    int ptrcount, pos = 0;
    uint8_t entropy[16];

    load(path, &lc, false);
    if (!lc.interp_entry)
        return;

    stackmem = (unsigned long*) mmap(NULL, 4096*4, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON | MAP_STACK | MAP_GROWSDOWN, -1, 0);

    if (stackmem == MAP_FAILED)
        perror("mmap");

    stack = (unsigned long*) (((char*) stackmem) + 4096*4 - sizeof(unsigned long));

    // AT_*
    ptrcount = 10*2;
    ptrcount++; // argc
    ptrcount += 1; // argv

    ptrcount++;

    // Ensure 16-byte alignment
    if (ptrcount % 2 == 0)
        ptrcount++;

    stack -= ptrcount;

    stack[pos++] = 1; // argc
    stack[pos++] = (unsigned long) path;
    stack[pos++] = 0;

    stack[pos++] = 0;

    stack[pos++] = AT_PHDR;
    stack[pos++] = lc.exec_phstart;

    stack[pos++] = AT_PHENT;
    stack[pos++] = lc.exec_phentsize;

    stack[pos++] = AT_PHNUM;
    stack[pos++] = lc.exec_phnum;

    stack[pos++] = AT_ENTRY;
    stack[pos++] = lc.exec_entry;

    stack[pos++] = AT_BASE;
    stack[pos++] = lc.interp_base;

    stack[pos++] = AT_PAGESZ;
    stack[pos++] = 4096;

    stack[pos++] = AT_FLAGS;
    stack[pos++] = 0;

    stack[pos++] = AT_RANDOM;
    stack[pos++] = (unsigned long) entropy;

    stack[pos++] = AT_IGNORE;
    stack[pos++] = sockfd;

    stack[pos++] = AT_NULL;
    stack[pos++] = 0;

    JUMPX(stack, lc.interp_entry);
}

void load(const char* path, struct loader_context* lc, bool isInterp)
{
    ElfW(Ehdr) elfHdr;
    void* phdrs = NULL;

    int fd = open(path, O_RDONLY);
    uintptr_t slide, base;

    if (fd == -1)
    {
        perror("open");
        return;
    }

    if (read(fd, &elfHdr, sizeof(elfHdr)) != sizeof(elfHdr))
    {
        perror("read");
        goto out;
    }

    if (memcmp(elfHdr.e_ident, ELFMAG, SELFMAG) != 0 || elfHdr.e_ident[EI_CLASS] != MY_ELF_CLASS)
    {
        puts("Wrong ELF signature\n");
        goto out;
    }

    if (elfHdr.e_type != ET_DYN)
    {
        puts("Only position independent ELF are supported\n");
        goto out;
    }
    if (!elfHdr.e_phoff)
    {
        puts("ELF is not loadable\n");
        goto out;
    }

    phdrs = malloc(elfHdr.e_phentsize * elfHdr.e_phnum);
    long a = pread(fd, phdrs, elfHdr.e_phentsize * elfHdr.e_phnum, elfHdr.e_phoff);
    if (a != elfHdr.e_phentsize * elfHdr.e_phnum)
    {
        puts("Failed to read Elf phdrs\n");
        goto out;
    }

    // First, get total virtual range needed
    uintptr_t minAddr = UINTPTR_MAX, maxAddr = 0;

    for (int i = 0; i < elfHdr.e_phnum; i++)
    {
        ElfW(Phdr)* phdr = (ElfW(Phdr)*) (((char*) phdrs) + (i * elfHdr.e_phentsize));

        if (phdr->p_type == PT_LOAD)
        {
            if (phdr->p_vaddr < minAddr)
                minAddr = ELF_PAGESTART(phdr->p_vaddr);
            if (phdr->p_vaddr + phdr->p_memsz > maxAddr)
                maxAddr = phdr->p_vaddr + phdr->p_memsz;
        }
        else if (phdr->p_type == PT_INTERP && isInterp)
        {
            puts("Interp with PT_INTERP?\n");
            goto out;
        }
    }
    if (maxAddr == 0)
    {
        puts("No PT_LOAD headers?\n");
        goto out;
    }

    base = (uintptr_t) mmap(NULL, maxAddr-minAddr, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == (uintptr_t) MAP_FAILED)
    {
        perror("mmap");
        puts("Cannot reserve 0x%lx bytes in memory\n");
        goto out;
    }
    slide = base - minAddr;

    for (int i = 0; i < elfHdr.e_phnum; i++)
    {
        ElfW(Phdr)* phdr = (ElfW(Phdr)*) (((char*) phdrs) + (i * elfHdr.e_phentsize));

        if (phdr->p_type == PT_LOAD)
        {
            int prot = 0;
            int flags = MAP_FIXED;
            void* result;

            uintptr_t addr = phdr->p_vaddr + slide;
            uintptr_t size = phdr->p_filesz + ELF_PAGEOFFSET(phdr->p_vaddr);
            uintptr_t memsize = phdr->p_memsz + ELF_PAGEOFFSET(phdr->p_vaddr);
            uintptr_t off = phdr->p_offset - ELF_PAGEOFFSET(phdr->p_vaddr);

            addr = ELF_PAGESTART(addr);

            if (phdr->p_flags & PF_X)
                prot |= PROT_EXEC;
            if (phdr->p_flags & PF_W)
                prot |= PROT_WRITE;
            if (phdr->p_flags & PF_R)
                prot |= PROT_READ;

            flags |= MAP_PRIVATE;

            bool needszeroing = size != ELF_PAGEALIGN(size);

            if (needszeroing)
                prot |= PROT_WRITE;
            if (mprotect((void*) (addr), memsize, prot) == -1)
            {
                perror("mprotect");
            }

            result = mmap((void*) addr, size, prot, flags, fd, off);
            if (result == MAP_FAILED)
            {
                perror("mmap");
                goto out;
            }

            // Based on experiments, when we provide a size that is less than a multiple of page size
            // mmap() will map up to the whole page of file data anyway. Many ELF files, including ld.so,
            // however rely on the rest of the page being zeroed out.
            if (needszeroing)
            {
                memset((void*)(addr + size), 0, ELF_PAGEALIGN(size) - size);
                if (!(phdr->p_flags & PF_W))
                    mprotect((void*) (addr), memsize, prot & ~PROT_WRITE);
            }
        }
        else if (phdr->p_type == PT_INTERP)
        {
            char* interp = malloc(phdr->p_filesz + 1);

            if (pread(fd, interp, phdr->p_filesz, phdr->p_offset) != phdr->p_filesz)
            {
                free(interp);
                perror("reading PT_INTERP");
                goto out;
            }
            interp[phdr->p_filesz] = '\0';

            load(interp, lc, true);

            free(interp);
        }
    }

    if (isInterp)
    {
        lc->interp_base = base;
        lc->interp_entry = slide + elfHdr.e_entry;
    }
    else
    {
        lc->exec_phstart = slide + elfHdr.e_phoff;
        lc->exec_phentsize = elfHdr.e_phentsize;
        lc->exec_phnum = elfHdr.e_phnum;
        lc->exec_entry = slide + elfHdr.e_entry;
    }

out:
    free(phdrs);
    close(fd);
}

void main(int sockfd)
{
    char path[256] = { 0 };
    char dummy;
    if(read(sockfd, path, sizeof(path)) <= 0)
    {
        puts("Failed to receive the payload path\n");
        return;
    }
    write(sockfd, &dummy, sizeof(dummy));
    run(path, sockfd);
}