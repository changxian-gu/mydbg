#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linenoise.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/personality.h>
#include <map>
#include <sys/user.h>

//registers

std::map<std::string, int> reg_map = {
	{"r15", 0}, {"r14", 1}, {"r13", 2}, {"r12", 3}, {"rbp", 4},
	{"rbx", 5}, {"r11", 6}, {"r10", 7 }, {"r9", 8}, {"r8", 9}, 
	{"rax", 10}, {"rcx", 11}, {"rdx", 12}, {"rsi", 13}, {"rdi", 14}, 
	{"orig_rax", 15},{"rip", 16}, {"cs", 17}, {"eflags", 18}, 
	{"rsp", 19}, {"ss", 20}, {"fs_base", 21}, {"gs_base", 22}, 
	{"ds", 23}, {"es", 24}, {"fs", 25}, {"gs", 26}
};

uint64_t get_register_value_by_name(pid_t pid, char* name) {
	struct user_regs_struct regs;
	uint64_t *p = (uint64_t *)&regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	uint64_t val = *(p + reg_map[name]);
	printf("%s : %p\n", name, (void *)val);
	return val;
}

void set_register_value_by_name(pid_t pid, char* name, uint64_t val) {
	struct user_regs_struct regs;
	uint64_t *p = (uint64_t *)&regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	*(p + reg_map[name]) = val;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}
//registers end

//memory
void get_memory_value(pid_t pid, uint64_t addr) {
	uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	printf("memory at %p : %p\n", (void *)addr, (void *)data);
}

void set_memory_value(pid_t pid, uint64_t addr, uint64_t data) {
	ptrace(PTRACE_POKEDATA, pid, addr, data);
	printf("change memory at %p to %p\n", (void *)addr, (void *)data); 
}

//breakpoint
class Breakpoint {
private:
	pid_t pid;
	uint64_t addr;
	uint8_t pre_data;
	bool on;
public:
	Breakpoint(){}
	Breakpoint(pid_t pid, uint64_t addr):pid(pid), addr(addr), on(false) {}

	void set_breakpoint() {
		uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
		pre_data = (uint8_t)(data & 0xff);
		data = ((data & (~0xff)) | 0xcc);
		ptrace(PTRACE_POKEDATA, pid, addr, data);
		on = true;
	}

	void unset_breakpoint() {
		uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
		data = (data & (~0xff)) | pre_data;
		ptrace(PTRACE_POKEDATA, pid, addr, data);
		on = false;
	}

	bool is_enabled() {
		return on;
	}
};

//breakpoint end

//debugger
class Debugger {
private:
	pid_t pid;
	std::map<uint64_t, Breakpoint> breakpoints;
public:
	Debugger() {}
	Debugger(pid_t pid):pid(pid) {}

	void debug() {
		int wait_status;
		waitpid(pid, &wait_status, 0);
		size_t bufsize = 128;
		char* buffer= (char *)malloc(bufsize * sizeof(char));
		size_t len;
		printf("mydbg> ");
		while ((len = getline(&buffer, &bufsize, stdin)) != 0) {
			buffer[len - 1] = '\0';
			execute_cmd(buffer);
			printf("mydbg> ");
		}
	}

	void execute_cmd(char* line) {
		char *token = strtok(line, " ");
		if (strcmp(token, "continue") == 0) {
			execute_continue();
		} else if (strcmp(token, "break") == 0) {
			token = strtok(NULL, " ");
			printf("-----%p-----\n",(void *)strtoul(token, 0, 16));
			set_breakpoint_addr(strtoul(token, 0, 16));  
		} else if (strcmp(token, "register") == 0) {
			token = strtok(NULL, " ");
			if (strcmp(token, "get") == 0) {
				token = strtok(NULL, " ");
				get_register_value_by_name(pid, token);
			} else if (strcmp(token, "set") == 0) {
				token = strtok(NULL, " ");
				char *reg = token;
				token = strtok(NULL, " ");
				set_register_value_by_name(pid, reg, strtoul(token, 0, 16));
			}
		} else if (strcmp(token, "memory") == 0) {
			token = strtok(NULL, " ");
			if (strcmp(token, "get") == 0) {
				token = strtok(NULL, " ");
				get_memory_value(pid, strtoul(token, 0, 16));
			} else if (strcmp(token, "set") == 0) {
				token = strtok(NULL, " ");
				char *t_addr = token;
				token = strtok(NULL, " ");
				set_memory_value(pid, strtoul(t_addr, 0, 16), strtoul(token, 0, 16));
			}
		} else {
			printf("No such command!!!\n");
		}			
	}

	void step_over_breakpoint() {
		uint64_t pc = get_register_value_by_name(pid, (char *)"rip");
		pc--;
		if (breakpoints.count(pc)) {
			Breakpoint t_bp = breakpoints[pc];
			if (t_bp.is_enabled()){
				set_register_value_by_name(pid, (char *)"rip", pc);
				t_bp.unset_breakpoint();
				ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
				int wait_status;
				waitpid(pid, &wait_status, 0);
				t_bp.set_breakpoint();
			}
		}
	}

	void execute_continue() {
		step_over_breakpoint();
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		int wait_status;
		waitpid(pid, &wait_status, 0);
	}

	void set_breakpoint_addr(uint64_t addr) {
		printf("%d breakpoint at address %p\n", (int)pid, (void*)addr);
		Breakpoint bp(pid, addr);
		bp.set_breakpoint();
		breakpoints[addr] = bp;
	}
};


//debugger end

int main(int argc, char* argv[]){
	if (argc < 2) {
		printf("No Program Found!!\n");
		return -1;
	}
	char* prog = argv[1];
	pid_t pid = fork();
	if (pid == 0) {
		personality(ADDR_NO_RANDOMIZE);
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl(prog, prog, NULL);
	} else if (pid >= 1) {
		printf("%d", (int)pid);
		Debugger dbg(pid);
		dbg.debug();
	}
}
