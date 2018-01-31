#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sched.h>

#include "ptrace.h"
#include "syscall.h"

/*
 * on how to handle clone https://github.com/lattera/glibc/blob/master/sysdeps/unix/sysv/linux/x86_64/clone.S
 */

#ifdef DEBUG
#define debug(fmt, ...) do { \
    fprintf(stderr, "[%s:%d:%s()] " fmt, __FILE__,__LINE__, __func__, ##__VA_ARGS__); \
} while (0)
#else
#define debug(...)
#endif

#define info(fmt, ...) do { \
    fprintf(stderr, "[+ %s] " fmt,  __func__, ##__VA_ARGS__); \
} while (0)

struct {
    int pid;
    char *payload;
} settings = { .pid = -1, .payload = NULL };

void parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "p:f:")) != -1) {
        switch (opt) {
            case 'p':
                settings.pid = atoi(optarg);
                break;
            case 'f':
                settings.payload = strdup(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-p pid]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (settings.pid < 0) {
        fprintf(stderr, "Cant attach to pid %d\n", settings.pid);
        exit(EXIT_FAILURE); 
    }
    if (!settings.payload) {
        fprintf(stderr, "Missing path to payload file\n");
        exit(EXIT_FAILURE);
    }
}

void print_memory_map(struct ptrace_info *info)
{
    struct mem_map_entry *ent, *ptr;
    ent = get_process_memory(info);
    mem_map_foreach(ent, ptr) {
        debug("%-18p %07lx %c%c%c %s\n",
                ptr->addr,
                ptr->size,
                ptr->perms & MEM_PERM_READ ? 'r' : '-',
                ptr->perms & MEM_PERM_WRITE ? 'w' : '-',
                ptr->perms & MEM_PERM_EXEC ? 'x' : '-',
                ptr->pathname);
    }
    debug("%d entries\n", mem_map_length(ent));

    mem_maps_free(ent);
}

uint64_t inject_code(struct ptrace_info *info, uint8_t *code, size_t code_len)
{
    struct user_regs_struct regs, tmpregs;
    uint8_t orig_code[code_len];

    ptrace_getregs(info, &regs);

    ptrace_readmem(info, (void *)regs.rip, orig_code, sizeof(orig_code));
    ptrace_writemem(info, (void *)regs.rip, code, code_len);

    ptrace_continue(info);

    ptrace_writemem(info, (void *)regs.rip, orig_code, sizeof(orig_code));
    ptrace_getregs(info, &tmpregs);
    ptrace_setregs(info, &regs);

    return tmpregs.rax;
}

uint64_t inject_mmap(struct ptrace_info *info, int size, int prot)
{
    uint8_t code[1024];
    int code_len;

    code_len = asm_mmap(code, 0, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    code_len += int3(code + code_len);

    return inject_code(info, code, code_len);
}

uint64_t inject_munmap(struct ptrace_info *info, uint64_t addr, uint64_t len)
{
    uint8_t code[1024];
    int code_len;

    code_len = asm_munmap(code, addr, len);
    code_len += int3(code + code_len);

    return inject_code(info, code, code_len);
}

void disas_code_at_addr(struct ptrace_info *info, uint64_t addr, int len, int num_instructions)
{
    uint8_t buf[len];

    ptrace_readmem(info, (void *)addr, buf, len);
    disasm(buf, len, addr, num_instructions);
}

void step_until_no_longer_inside_SO(struct ptrace_info *info, int max_steps)
{
    int i;
    struct user_regs_struct regs;

    for (i = 0; i < max_steps; ++i) {
        if (ptrace_step(info) == -1)
            perror("ptrace_step");

        ptrace_getregs(info, &regs);
        if (!mommy_am_i_inside_a_SO(info))
            break;
    }

    debug("stepped %d instructions to address %llx\n", i, regs.rip);
}

void inject_clone(struct ptrace_info *info)
{
    FILE *fp;
    uint8_t code_to_exec[1024], clone_code[1024];
    int stack_size = 2 * PAGE_SIZE, clone_code_size, codelen;
    uint64_t stack_addr, text_addr, bootstrap;
    struct user_regs_struct orig_regs, regs;

    if (!(fp = fopen(settings.payload, "r"))) {
        perror("fopen");
        return;
    }
    codelen = fread(code_to_exec, 1, sizeof(code_to_exec), fp);
    fclose(fp);

    step_until_no_longer_inside_SO(info, 1024);

    // save registers in their original state
    ptrace_getregs(info, &orig_regs);

    text_addr = inject_mmap(info, PAGE_SIZE, PROT_READ|PROT_EXEC);
    stack_addr = inject_mmap(info, stack_size, PROT_READ|PROT_WRITE);
    bootstrap = inject_mmap(info, PAGE_SIZE, PROT_READ|PROT_EXEC);
    debug("allocated memory for text (%lx), stack (%lx), and bootstrap code: (%lx)\n", 
            text_addr, stack_addr, bootstrap);

    debug("writing code (%d bytes) to execute to target process at address %lx\n", codelen, text_addr);
    ptrace_writemem(info, (void *)text_addr, code_to_exec, codelen);

    clone_code_size = asm_clone(clone_code, stack_addr + stack_size, text_addr);
    debug("writing clone (%d bytes) syscall to target proces\n", clone_code_size);
    ptrace_writemem(info, (void *)bootstrap, clone_code, clone_code_size);

    debug("execute stub code %lx\n", bootstrap);
    disas_code_at_addr(info, bootstrap, clone_code_size, 99999);
    disas_code_at_addr(info, text_addr, codelen, 99999);

    regs = orig_regs;
    regs.rip = bootstrap;
    ptrace_setregs(info, &regs);
    ptrace_continue(info);

    //debug("munmapping temporary sub code\n");
    //inject_munmap(info, bootstrap, PAGE_SIZE);

    debug("restoring context in main thread\n");
    ptrace_setregs(info, &orig_regs);
}

void do_the_inject_thing(struct ptrace_info *info)
{
    debug("memory map before injection\n");
    print_memory_map(info);

    inject_clone(info);

    debug("memory map after injection\n");
    print_memory_map(info);
}

int main(int argc, char *argv[])
{
    struct ptrace_info *info;

    parse_args(argc, argv);

    info = ptrace_attach(settings.pid);
    if (!info) {
        perror("Failed to attach");
        return 1;
    }
    debug("attached to %d\n", settings.pid);

    do_the_inject_thing(info);

    ptrace_detach(info);
    ptrace_free(info);
    debug("detached from %d\n", settings.pid);

    free(settings.payload);

    return 0;
}
