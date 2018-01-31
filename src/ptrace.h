#ifndef __PTRACE_H
#define __PTRACE_H

#include <stdint.h>
#include <sys/user.h>

struct ptrace_info;

#define MEM_PERM_READ  (1 << 2)
#define MEM_PERM_WRITE (1 << 1)
#define MEM_PERM_EXEC  (1 << 0)

#define mem_map_length(ents) *(((uint32_t *)ents) - 1)
#define mem_map_foreach(ents, ptr) \
	for ((ptr) = (ents); (ptr) < (ents) + mem_map_length(ents); ++(ptr))

struct mem_map_entry {
	void *addr;
	size_t size;
	uint8_t perms;
	char *pathname;
};

extern struct ptrace_info *ptrace_attach(int pid);
extern long ptrace_detach(struct ptrace_info *info);
extern void ptrace_free(struct ptrace_info *info);
extern int ptrace_readmem(struct ptrace_info *info, void *addr, void *buf, size_t n);
extern int ptrace_writemem(struct ptrace_info *info, void *addr, void *src, size_t n);
extern struct mem_map_entry *get_process_memory(struct ptrace_info *info);
extern void mem_maps_free(struct mem_map_entry *ent);
extern int ptrace_getregs(struct ptrace_info *info, struct user_regs_struct *regs);
extern int ptrace_setregs(struct ptrace_info *info, struct user_regs_struct *regs);
extern int ptrace_continue_no_block(struct ptrace_info *info);
extern int ptrace_continue(struct ptrace_info *info);
extern int ptrace_step(struct ptrace_info *info);
extern int ptrace_step_n(struct ptrace_info *info, int n);
extern int mommy_am_i_inside_a_SO(struct ptrace_info *info);

#endif /* end of include guard: __PTRACE_H */
