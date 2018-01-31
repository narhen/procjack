#ifndef __SYSCALL_H
#define __SYSCALL_H

#define syscall1(out_buf, syscall_no, a) \
    asm_syscall(1, out_buf, syscall_no, a)
#define syscall2(out_buf, syscall_no, a, b) \
    asm_syscall(2, out_buf, syscall_no, a, b)
#define syscall3(out_buf, syscall_no, a, b, c) \
    asm_syscall(3, out_buf, syscall_no, a, b, c)
#define syscall4(out_buf, syscall_no, a, b, c, d) \
    asm_syscall(4, out_buf, syscall_no, a, b, c, d)
#define syscall5(out_buf, syscall_no, a, b, c, d, e) \
    asm_syscall(5, out_buf, syscall_no, a, b, c, d, e)
#define syscall6(out_buf, syscall_no, a, b, c, d, e, f) \
    asm_syscall(6, out_buf, syscall_no, a, b, c, d, e, f)

#define asm_mmap(out_buf, addr, len, prot, flags, fd, offset) \
    syscall6(out_buf, 9, addr, len, prot, flags, fd, offset)
#define asm_munmap(out_buf, addr, len) \
    syscall2(out_buf, 11, addr, len)

extern int int3(uint8_t *buf);
extern int mov_rax(uint64_t num, uint8_t *buf);
extern int mov_rdi(uint64_t num, uint8_t *buf);
extern int mov_rsi(uint64_t num, uint8_t *buf);
extern int mov_rdx(uint64_t num, uint8_t *buf);
extern int mov_r10(uint64_t num, uint8_t *buf);
extern int mov_r8(uint64_t num, uint8_t *buf);
extern int mov_r9(uint64_t num, uint8_t *buf);
extern int asm_syscall(int num_args, uint8_t *out_buf, int syscall_no, ...);
extern int asm_clone(uint8_t *out_buf, uint64_t stack_addr, uint64_t thread_code);
extern int disasm(uint8_t *code, int code_len, uint64_t start_addr, int num_instructions);

#endif
