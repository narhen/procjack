CC = gcc
CFLAGS = -Wall -lcapstone
AS = nasm
ASFLAGS = -f bin

all: inject dummy count

debug: CFLAGS += -DDEBUG -g
debug: all

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

inject: inject.o ptrace.o syscall.o
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

dummy: dummy.o
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

count: count.asm
	$(AS) $^ $(ASFLAGS) -o $@
	#$(AS) $^ -f elf64 -o count.o
	#ld -m elf_x86_64 count.o -o count

clean:
	-$(RM) *.o inject dummy count
