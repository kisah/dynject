all: ../build/magic.bin

../artifacts/magic.elf: *.c *.h
	gcc start.c std.c magic.c -fno-builtin -fpic -fpie -pie -fno-jump-tables -fno-stack-protector -static -nostdlib -T linker.ld -o $@

../build/magic.bin: ../artifacts/magic.elf
	objcopy -O binary $< $@

.PHONY: all
