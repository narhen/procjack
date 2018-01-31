#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sched.h>

#include <capstone/capstone.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

int int3(uint8_t *buf)
{
    uint8_t int3[] = { 0xcc };
    memcpy(buf, int3, sizeof(int3));
    return sizeof(int3);
}

int mov_rax(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_rdi(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_rsi(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_rdx(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_r10(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_r8(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int mov_r9(uint64_t num, uint8_t *buf)
{
    uint8_t opc[] = { 0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint64_t *val = (uint64_t *)&buf[2];
    memcpy(buf, opc, sizeof(opc));
    *val = num;
    return sizeof(opc);
}

int asm_syscall(int num_args, uint8_t *out_buf, int syscall_no, ...)
{
    va_list ap;
    int arg_no;
    uint64_t arg;
    uint8_t *bufptr = out_buf;
    uint8_t _syscall[] = { 0x0f, 0x05 };

    int (*reg_init_func[])(uint64_t, uint8_t *) = {
        mov_rdi,
        mov_rsi,
        mov_rdx,
        mov_r10,
        mov_r8,
        mov_r9
    };
    num_args = min(num_args, 6);

    va_start(ap, syscall_no);
    for (arg_no = 0; arg_no < num_args; ++arg_no) {
        arg = va_arg(ap, uint64_t);
        bufptr += reg_init_func[arg_no](arg, bufptr);
    }
    va_end(ap);

    bufptr += mov_rax(syscall_no, bufptr);
    memcpy(bufptr, _syscall, sizeof(_syscall));
    bufptr += sizeof(_syscall);

    return (int)(bufptr - out_buf);
}

int asm_clone(uint8_t *out_buf, uint64_t stack_addr, uint64_t thread_code)
{
    int syscall_len;
    uint8_t stub[] = {
        0x48, 0x85, 0xc0, // test rax,rax
        0x74, 0x01, // jz +1 (skip int3 for thread)
        //0x90, // nop
        0xcc, // int3
        0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x123456781234578
        0xff, 0xe0 // jmp rax
    };
    uint64_t *jump_target = (uint64_t *)&stub[8];

    *jump_target = thread_code;

    syscall_len = asm_syscall(5, out_buf, 56, CLONE_SIGHAND|CLONE_FS|CLONE_VM|CLONE_FILES|CLONE_THREAD, 
            stack_addr, 0, 0, 0);

    memcpy(out_buf + syscall_len, stub, sizeof(stub));
    return syscall_len + sizeof(stub);
}

int disasm(uint8_t *code, int code_len, uint64_t start_addr, int num_instructions)
{
    csh handle;
    cs_insn *insn;
    size_t count, j;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    count = cs_disasm(handle, code, code_len, start_addr, 0, &insn);
    if (count <= 0) {
        printf("ERROR: Failed to disassemble given code!\n");
        cs_close(&handle);
        return 0;
    }

    for (j = 0; j < min(count, num_instructions); j++) {
        printf("0x%lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                insn[j].op_str);
    }

    cs_free(insn, count);

    return 0;
}
