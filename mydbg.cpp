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

//breakpoint
class Breakpoint {
private:
	pid_t pid;
	uint64_t addr;
	uint8_t pre_data;
public:
	Breakpoint(){}
	Breakpoint(pid_t pid, uint64_t addr):pid(pid), addr(addr) {}

	void set_breakpoint() {
		uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
		printf("Addr : %p, Data : %p\n", (void *)addr, data);
		pre_data = (uint8_t)(data & 0xff);
		data = ((data & (~0xff)) | 0xcc);
		printf("Addr : %p, Data : %p\n", (void *)addr, data);
		ptrace(PTRACE_POKEDATA, pid, addr, data);
	}

	void unset_breakpoint() {
		uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
		data = (data & (~0xff)) | pre_data;
		ptrace(PTRACE_POKEDATA, pid, addr, data);
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
		if (strcmp(line, "continue") == 0) {
			execute_continue();
		} else if (strcmp(line, "break") == 0) {
			set_breakpoint_addr(0x555555554000);  
		} else {
			printf("No such command!!!\n");
		}			
	}

	void execute_continue() {
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
