// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/pmap.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "map", "Show mappings in detail", mon_show_mappings },
	{ "change", "Change to new priviledge bits", mon_change },
	{ "clear", "Remove certain priviledge bits", mon_clear },
	{ "set", "Set some priviledge bits", mon_set },
	{ "dump", "Dump current content of specified memory", mon_dump },
	{ "test", "For develope use", mon_test },
	{ "bt", "Backtrace the stack", mon_backtrace}
};

/***** Implementations of basic kernel monitor commands *****/
int mon_test(int argc, char **argv, struct Trapframe *tf) {
	char *s = "Hello";
	outb(0x3F8, 'H');
	outb(0x3F8, 'e');
	outb(0x3F8, 'l');
	outb(0x3F8, 'l');
	outb(0x3F8, '\b');
	char c = getchar();
	outb(0x3F8, '\b');
	outb(0x3F8, '\b');
	outb(0x3F8, '\b');
	outb(0x3F8, 'o');
	outb(0x3F8, ',');

	outb(0x3F8, '\n');
	return 0;
}

int mon_dump(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 4) {
		cprintf("ARGS Error!\n");
		return -1;
	}
	char *buf;
	char *type = argv[3];
	uintptr_t beg;
	uintptr_t end;
	if (type[0] == 'V') {
		beg = strtol(argv[1], &buf, 16);
		end = strtol(argv[2], &buf, 16);
	}
	else if (type[0] == 'P') {
		beg = strtol(argv[1] + KERNBASE, &buf, 16);
		end = strtol(argv[2] + KERNBASE, &buf, 16);
	} 
	else{
		cprintf("ARGS Error!\n");
		return -1;
	}

	beg = ROUNDUP(beg, 4);
	uintptr_t p = beg;
	for (; p < end; p+=4) {
		cprintf("[%p]:0x%x\n", p, *(uint32_t*)p);
	}
	return 0;
}

int mon_show_mappings(int argc, char **argv, struct Trapframe *tf){
	if (argc != 3)
		panic("ARGS error!");
	char *buf;
	uintptr_t abeg = strtol(argv[1], &buf, 16);// readnum(argv[1], 16);
	uintptr_t aend = strtol(argv[2], &buf, 16);

	for (uintptr_t a = abeg; a<aend; a+=PGSIZE){
		pte_t *pte = pgdir_walk(kern_pgdir, (void*)a, 0);
		if (pte && (*pte & PTE_P)) {
			physaddr_t pbase = PTE_ADDR(*pte);
			cprintf(" [%p-%p]: [%p-%p] ", a, a+PGSIZE-1, pbase, pbase+PGSIZE-1);
			if (*pte & PTE_U) cputchar('U');
			else cputchar('-');
			cputchar('R');
			if (*pte & PTE_W) cputchar('W');
			else cputchar('-');
			cputchar('\n');
		}
	}
	return 0;
}

int mon_change(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3)
		panic("ARGS error!");
	char *buf;
	uintptr_t addr = strtol(argv[1], &buf, 16);// readnum(argv[1], 16);
	uint32_t newperm = strtol(argv[2], &buf, 10);// readnum(argv[2], 10);

	pte_t *pte = pgdir_walk(kern_pgdir, (void*)addr, 0);
	if (pte == NULL || !(*pte & PTE_P))
		return -1;
	*pte &= (~0xfff);
	*pte |= newperm;
	return 0;
}

int mon_set(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3)
		panic("ARGS error!");
	char *buf;
	uintptr_t addr = strtol(argv[1], &buf, 16);// readnum(argv[1], 16);
	uint32_t addperm = strtol(argv[2], &buf, 10);// readnum(argv[2], 10);

	pte_t *pte = pgdir_walk(kern_pgdir, (void*)addr, 0);
	if (pte == NULL || !(*pte & PTE_P))
		return -1;
	*pte |= addperm;
	return 0;
}


int mon_clear(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3)
		panic("ARGS error!");
	char *buf;
	uintptr_t addr = strtol(argv[1], &buf, 16);// readnum(argv[1], 16);
	uint32_t rmperm = strtol(argv[2], &buf, 10);// readnum(argv[2], 10);

	pte_t *pte = pgdir_walk(kern_pgdir, (void*)addr, 0);
	if (pte == NULL || !(*pte & PTE_P))
		return -1;
	*pte &= (~rmperm);
	return 0;
}

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int mon_backtrace(int argc, char **argv, struct Trapframe *tf) {
	
	int *ebp = (int*)read_ebp();
	cprintf("Stack backtrace:\n");
	struct Eipdebuginfo info;
	while(ebp != 0){
		cprintf("  ebp %08x", (int)ebp);
		cprintf("  eip %08x", *(ebp + 1));
		cprintf("  args ");
		cprintf("%08x ", *(ebp + 2));
		cprintf("%08x ", *(ebp + 3));
		cprintf("%08x ", *(ebp + 4));
		cprintf("%08x ", *(ebp + 5));
		cprintf("%08x\n", *(ebp + 6));
		debuginfo_eip(ebp[1], &info);
    	cprintf("     %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, 
			info.eip_fn_namelen, info.eip_fn_name, ebp[1] - info.eip_fn_addr);
		ebp = (int*)(*ebp);
	}
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
