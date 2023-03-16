.section .text
.global _start
_start:
    mov $9, %rax          # mmap
    xor %rdi, %rdi        # NULL address
    mov $8192, %rsi       # size
    mov $7, %rdx          # PROT_READ | PROT_WRITE | PROT_EXEC
    mov $2, %r10          # MAP_PRIVATE
    xor %r9, %r9          # offset
    syscall               # magic fd passed in r8 by the injector
    mov %rax, %rbx

    mov $3, %rax          # close
    mov %r8, %rdi         # magic fd
    syscall

    mov $9, %rax          # mmap
    xor %rdi, %rdi        # NULL address
    mov $16384, %rsi      # size
    mov $3, %rdx          # PROT_READ | PROT_WRITE
    mov %r12, %r10        # MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN
    mov $-1, %r8          # fd
    xor %r9, %r9
    syscall

    add $16384, %rax
    mov %rax, %rsi        # stack
    mov $56, %rax         # clone
    mov %r13, %rdi        # CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_IO
    syscall

    test %rax, %rax
    jnz 1f
    mov %r14, %rdi
    call *%rbx
1:
    int3
