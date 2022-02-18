#include <stdio.h>
#include <string.h>
#include "linenoise.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

void execute_cmd(pid_t pid, char* line);
void execute_continue(pid_t pid);
void start_debug(pid_t pid);

void start_debug(pid_t pid) {
	int wait_status;
	waitpid(pid, &wait_status, 0);

	char* line = NULL;
	while ((line = linenoise("mydbg> ")) != NULL) {
		execute_cmd(pid, line);
		linenoiseHistoryAdd(line);
		linenoiseFree(line);
	}
}

void execute_cmd(pid_t pid, char* line) {
	if (strcmp(line, "continue") == 0) {
		execute_continue(pid);
	} else {
		printf("No such command!!!\n");
	}			
}

void execute_continue(pid_t pid) {
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	int wait_status;
	waitpid(pid, &wait_status, 0);
}



//breakpoint
class Breakpoint {
private:
	pid_t pid;
	uint64_t addr;
	uint8_t pre_data;
public:
	Breakpoint(pid_t pid, uint64_t addr);
	void set_breakpoint(pid_t pid, uint64_t addr);
	void unset_breakpoint(pid_t pid, uint64_t addr);
};

Breakpoint::Breakpoint(pid_t pid, uint64_t addr) {
	pid = pid;
	addr = addr;
}

void Breakpoint::set_breakpoint(pid_t pid, uint64_t addr) {
	uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	pre_data = (uint8_t)(data & 0xff);
	data = (data & (~0xff)) | 0xcc;
	ptrace(PTRACE_POKEDATA, pid, addr, data);
}

void Breakpoint::unset_breakpoint(pid_t pid, uint64_t addr) {
	uint64_t data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	data = (data & (~0xff)) | pre_data;
	ptrace(PTRACE_POKEDATA, pid, addr, data);
}
//breakpoint end


int main(int argc, char* argv[]){
	if (argc < 2) {
		printf("No Program Found!!\n");
		return -1;
	}
	char* prog = argv[1];
	pid_t pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl(prog, prog, NULL);
	} else if (pid >= 1) {
		start_debug(pid);
	}
}