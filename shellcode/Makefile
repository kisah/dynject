all: ../build/shellcode.bin

../artifacts/shellcode.elf: shellcode.S
	gcc shellcode.S -T ../magic/linker.ld -static -nostdlib -o $@

../build/shellcode.bin: ../artifacts/shellcode.elf
	objcopy -O binary $< $@

.PHONY: all
