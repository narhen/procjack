#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "ptrace.h"

struct ptrace_info {
	int pid;
};

struct ptrace_info *ptrace_attach(int pid)
{
	struct ptrace_info *ret;

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
		return NULL;

	ret = calloc(1, sizeof(struct ptrace_info));
	ret->pid = pid;

	waitpid(pid, NULL, 0);
	return ret;
}

long ptrace_detach(struct ptrace_info *info)
{
	return ptrace(PTRACE_DETACH, info->pid);
}

void ptrace_free(struct ptrace_info *info)
{
	free(info);
}

static uint32_t read_word(struct ptrace_info *info, void *addr)
{
	uint32_t ret = ptrace(PTRACE_PEEKTEXT, info->pid, addr, NULL);
	if (ret == 0xffffffff && errno) {
		perror("peekdata");
	}
	return ret;
}

int ptrace_readmem(struct ptrace_info *info, void *addr, void *buf, size_t n)
{
	size_t i;
	uint32_t word;
	int wordsize = sizeof(word);
	uint64_t curaddr = (uint64_t)addr;
	uint8_t *bufptr = buf;

	for (i = 0; i + wordsize <= n; i += wordsize, curaddr += wordsize) {
		word = read_word(info, (void *)curaddr);
		memcpy(bufptr + i, &word, wordsize);
	}

	if (i < n) {
		word = read_word(info, (void *)curaddr);
		memcpy(bufptr + i, &word, n - i);
	}

	return (int)n;
}

static long write_word(struct ptrace_info *info, void *addr, uint32_t word)
{
	return ptrace(PTRACE_POKETEXT, info->pid, addr, (void *)(uint64_t)word);
}

int ptrace_writemem(struct ptrace_info *info, void *addr, void *src, size_t n)
{
	size_t i;
	uint32_t word;
	int wordsize = sizeof(word);
	uint64_t curaddr = (uint64_t)addr;
	uint8_t *srcptr = src;

	for (i = 0; i + wordsize <= n; i += wordsize, curaddr += wordsize, srcptr += wordsize) {
		if (write_word(info, (void *)curaddr, *((uint32_t *)srcptr)) == -1)
			return -1;
	}

	if (i < n) {
		word = read_word(info, (void *)curaddr);
		memcpy(&word, srcptr, n - i);
		if (write_word(info, (void *)curaddr, *((uint32_t *)srcptr)) == -1)
			return -1;
	}

	return (int)n;
}

static void parse_maps_ent(char *str, struct mem_map_entry *ent)
{
	int i;
	uint64_t start, end;
	char *str2, *token, *saveptr, *tmp;

	for (i = 0, str2 = str; ; str2 = NULL, ++i) {
		token = strtok_r(str2, " ", &saveptr);
		if (!token)
			break;

		switch (i) {
			case 0:
				tmp = strchr(token, '-');
				*tmp++ = 0;

				start = strtoul(token, NULL, 16);
				end = strtoul(tmp, NULL, 16);
				*--tmp = '-';

				ent->addr = (void *)start;
				ent->size = end - start;
				break;
			case 1:
				if (token[0] == 'r')
					ent->perms |= MEM_PERM_READ;
				if (token[1] == 'w')
					ent->perms |= MEM_PERM_WRITE;
				if (token[2] == 'x')
					ent->perms |= MEM_PERM_EXEC;
				break;
			case 5:
				ent->pathname = strdup(token);
				break;
		}
	}
}

struct mem_map_entry *get_process_memory(struct ptrace_info *info)
{
	char buf[1024];
	uint32_t *num;
	int num_ents = 20, i;
	struct mem_map_entry *ret, *current;
	FILE *fp;

	sprintf(buf, "/proc/%d/maps", info->pid);
	fp = fopen(buf, "r");
	if (!fp)
		return NULL;

	num = calloc(1, sizeof(struct mem_map_entry) * num_ents + sizeof(uint32_t));
	ret = current = (struct mem_map_entry *)((uint32_t *)num + 1);

	for (i = 0; fgets(buf, sizeof(buf), fp); ++i, ++current) {
		if (i >= num_ents) {
			num_ents += 10;
			num = realloc(num, num_ents * sizeof(struct mem_map_entry) + sizeof(uint32_t));
			ret = (struct mem_map_entry *)((uint32_t *)num + 1);
			current = ret + i;
		}

		if (strchr(buf, '\n'))
			*strchr(buf, '\n') = 0;
		parse_maps_ent(buf, current);
	}

	*num = i;
	return ret;
}

void mem_maps_free(struct mem_map_entry *ent)
{
	uint32_t *num, i;
	num = ((uint32_t *)ent) - 1;

	for (i = 0; i < *num; i++)
		free(ent[i].pathname);
	free(num);
}

int ptrace_getregs(struct ptrace_info *info, struct user_regs_struct *regs)
{
	return ptrace(PTRACE_GETREGS, info->pid, NULL, regs);
}

int ptrace_setregs(struct ptrace_info *info, struct user_regs_struct *regs)
{
	return ptrace(PTRACE_SETREGS, info->pid, NULL, regs);
}

int ptrace_continue_no_block(struct ptrace_info *info)
{
	if (ptrace(PTRACE_CONT, info->pid, NULL, NULL) == -1)
			return -1;
    return 0;
}

int ptrace_continue(struct ptrace_info *info)
{
	if (ptrace_continue_no_block(info) == -1)
			return -1;
	return waitpid(info->pid, NULL, 0);
}

static int step(struct ptrace_info *info)
{
    if (ptrace(PTRACE_SINGLESTEP, info->pid, NULL, NULL) == -1)
        return -1;
    return waitpid(info->pid, NULL, 0);
}

int ptrace_step_n(struct ptrace_info *info, int n)
{
    int i;

    for (i = 0; i < n; i++)
        if (step(info) == -1)
            return -1;
    return 0;
}

int ptrace_step(struct ptrace_info *info)
{
    return ptrace_step_n(info, 1);
}

int mommy_am_i_inside_a_SO(struct ptrace_info *info)
{
    int well_am_i = 0;
    struct mem_map_entry *mem_map, *ptr;
    struct user_regs_struct regs;

    mem_map = get_process_memory(info);
    ptrace_getregs(info, &regs);

    mem_map_foreach(mem_map, ptr) {
        uint64_t page_addr = (uint64_t)ptr->addr;
        if (regs.rip < page_addr || regs.rip >= page_addr + ptr->size)
            continue;

        if (ptr->pathname != NULL) {
            well_am_i = !strncmp(ptr->pathname, "/lib", 4)
                || !strncmp(ptr->pathname, "/usr/lib", 8);
        }
        break;
    }

    mem_maps_free(mem_map);
    return well_am_i;
}
