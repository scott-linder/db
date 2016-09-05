#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debugreg.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <udis86.h>
#include <unistd.h>

/*
 * Error helpers.
 */
void err_ret(const char *s) {
	perror(s);
}

void err_sys(const char *s) {
	err_ret(s);
	exit(1);
}

/*
 * Our instruction decoder requires us to yield bytes via callback, so we must
 * have a few globals to inform it where to look.
 */
static pid_t child;
static long ip;
static int ip_byte;

/*
 * Our version of ud_dissassemble which sets up global state.
 */
int db_dissassemble(ud_t *ud) {
	ip = ptrace(PTRACE_PEEKUSER, child,
		offsetof(struct user_regs_struct, rip));
	if (ip == -1) err_sys("peekuser rip");
	ip_byte = 0;
	ud_set_pc(ud, ip);
	return ud_disassemble(ud);
}

/*
 * Callback for udis86 which returns the next unread byte relative to the
 * current instruction pointer.
 *
 * This function is called indirectly by ud_dissassemble; to ensure all the
 * required globals are set properly, call db_dissassemble instead.
 */
int get_next_insn_byte(ud_t *ud) {
	// TODO: cache remaining bytes from last ptrace call, only calling
	// again if we run out
	long word = ptrace(PTRACE_PEEKDATA, child, ip + ip_byte++);
	return *(unsigned char *)&word;
}

/*
 * Setup to be traced and exec.
 */
void tracee(int argc, char *args[]) {
	char **argv = calloc(argc+1, sizeof(char*));
	memcpy(argv, args, argc*sizeof(char*));
	ptrace(PTRACE_TRACEME);
	execvp(argv[0], argv);
}

/*
 * Issue prompt and read until a non-zero length line is read.
 */
char *prompt_getline(char *prompt) {
	char *line; size_t n;
	do {
		printf("%s", prompt);
		line = NULL; n = 0;
		free(line);
		if (getline(&line, &n, stdin) == -1)
			err_sys("getline");
	} while (strlen(line) == 0);
	return line;
}

/*
 * Wait on the child until completing a single step.
 *
 * Returns true on success, false on process exit.
 */
bool singlestep(ud_t *ud) {
	int signal = 0, status;
	long dr6;
	char *line;
	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, child, 0, signal) == -1)
			err_sys("ptrace singlestep");
		if (waitpid(child, &status, __WALL) != child)
			err_sys("inner waitpid");

		if (WIFEXITED(status)) {
			fprintf(stderr, "child exited with status=%d\n",
					WEXITSTATUS(status));
			return false;
		} if (WIFSIGNALED(status)) {
			fprintf(stderr, "child terminated by signal=%d\n",
					WTERMSIG(status));
			return false;
		} else if WIFSTOPPED(status) {
			signal = WSTOPSIG(status);
			dr6 = ptrace(PTRACE_PEEKUSER, child,
				offsetof(struct user, u_debugreg[6]));
			if (dr6 == -1) err_sys("peekuser dr6");
			if (signal == SIGTRAP && dr6 == DR_STEP) {
				return true;
			} else {
				fprintf(stderr, "process will see signal=%d\n",
						signal);
				line = prompt_getline("suppress? (y/N) ");
				if (line[0] == 'y')
					signal = 0;
			}
		}
	}
}

/*
 * Attempt to calculate offset for register into `struct user` based on its
 * name as a string.
 *
 * Returns the offset if found, otherwise -1.
 */
long reg_offset(char *reg) {
#define IF_CMP_REGOFF(r) if (strcmp(reg, #r) == 0) \
				return (offsetof(struct user_regs_struct, r))
	IF_CMP_REGOFF(r15);
	else IF_CMP_REGOFF(r14);
	else IF_CMP_REGOFF(r13);
  	else IF_CMP_REGOFF(r12);
  	else IF_CMP_REGOFF(rbp);
  	else IF_CMP_REGOFF(rbx);
  	else IF_CMP_REGOFF(r11);
  	else IF_CMP_REGOFF(r10);
  	else IF_CMP_REGOFF(r9);
  	else IF_CMP_REGOFF(r8);
  	else IF_CMP_REGOFF(rax);
  	else IF_CMP_REGOFF(rcx);
  	else IF_CMP_REGOFF(rdx);
  	else IF_CMP_REGOFF(rsi);
  	else IF_CMP_REGOFF(rdi);
  	else IF_CMP_REGOFF(orig_rax);
  	else IF_CMP_REGOFF(rip);
  	else IF_CMP_REGOFF(cs);
  	else IF_CMP_REGOFF(eflags);
  	else IF_CMP_REGOFF(rsp);
  	else IF_CMP_REGOFF(ss);
  	else IF_CMP_REGOFF(fs_base);
  	else IF_CMP_REGOFF(gs_base);
  	else IF_CMP_REGOFF(ds);
  	else IF_CMP_REGOFF(es);
  	else IF_CMP_REGOFF(fs);
  	else IF_CMP_REGOFF(gs);
	else {
		return -1;
	}
#undef IF_CMP_REGOFF
}

/*
 * Wait for child to start the trace, and then interpret user commands.
 */
int tracer(ud_t *ud) {
	char *lastline = NULL, *line = NULL;
	bool alive = true;
	unsigned long addr, data;
	char reg[7];
	// When the tracee execs we will see a signal indicating it is stopped
	// and ready to be traced.
	if (waitpid(child, NULL, __WALL) != child)
		err_sys("initial waitpid");
	while (alive) {
		line = prompt_getline("(db) ");
		// If input is a blank line reuse previous input.
		if (line[0] == '\n' && lastline != NULL) {
			free(line);
			line = lastline;
		} else {
			free(lastline);
			lastline = line;
		}

		// All commands are identified by a single character.
		switch (line[0]) {
		case 's': // step
			if (!singlestep(ud)) return 0;
			// fallthrough
		case 'd': // dissassemble
			db_dissassemble(ud);
			printf("%016lx %s\n", ud_insn_off(ud), ud_insn_asm(ud));
			break;
		case 'r': // read register
			if (sscanf(&line[1], "%6s", reg) != 1) {
				fprintf(stderr, "invalid arguments");
				break;
			}
			if ((addr = reg_offset(reg)) == -1) {
				fprintf(stderr, "unknown register %s", reg);
				break;
			}
			errno = 0;
			data = ptrace(PTRACE_PEEKUSER, child, addr);
			if (errno != 0) err_ret("could not get data");
			else fprintf(stderr, "%lx\n", data);
			break;
		case 'w': // write register
			if (sscanf(&line[1], "%6s %lx", reg, &data) != 2) {
				fprintf(stderr, "invalid arguments");
				break;
			}
			if ((addr = reg_offset(reg)) == -1) {
				fprintf(stderr, "unknown register %s", reg);
				break;
			}
			if (ptrace(PTRACE_POKEUSER, child, addr, data) == -1)
				err_ret("could not write to register");
			break;
		case 'g': // get memory
			if (sscanf(&line[1], "%lx", &addr) != 1) {
				fprintf(stderr, "invalid arguments");
				break;
			}
			errno = 0;
			data = ptrace(PTRACE_PEEKDATA, child, addr);
			if (errno != 0) err_ret("could not get data");
			else fprintf(stderr, "%lx\n", data);
			break;
		case 'p': // poke memory
			if (sscanf(&line[1], "%lx %lx", &addr, &data) != 2) {
				fprintf(stderr, "invalid arguments");
				break;
			}
			if (ptrace(PTRACE_POKEDATA, child, addr, data) == -1)
				err_ret("could not poke data");
			break;
		case 'e': // exit
			alive = false;
			break;
		case 'h': // help
			fprintf(stderr, \
				"commands:\n"
				"\ts             | step single instruction\n"
				"\td             | dissassemble current instruction\n"
				"\tr <reg>       | read register\n"
				"\tw <reg> <val> | write register\n"
				"\tg <adr>       | poke register\n"
				"\tp <adr> <val> | poke memory\n"
				"\te             | exit\n"
				"registers:\n"
				"\tr15\n"
  				"\tr14\n"
  				"\tr13\n"
  				"\tr12\n"
  				"\trbp\n"
  				"\trbx\n"
  				"\tr11\n"
  				"\tr10\n"
  				"\tr9\n"
  				"\tr8\n"
  				"\trax\n"
  				"\trcx\n"
  				"\trdx\n"
  				"\trsi\n"
  				"\trdi\n"
  				"\torig_rax\n"
  				"\trip\n"
  				"\tcs\n"
  				"\teflags\n"
  				"\trsp\n"
  				"\tss\n"
  				"\tfs_base\n"
  				"\tgs_base\n"
  				"\tds\n"
  				"\tes\n"
  				"\tfs\n"
  				"\tgs\n"
			       );
		}
	}
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s command\n", argv[0]);
		return 1;
	}

	// Initialize instruction decoding library for 64bit encoding with
	// AT&T style output, with bytes taken from our callback.
	ud_t ud;
	ud_init(&ud);
	ud_set_mode(&ud, 64);
	ud_set_syntax(&ud, UD_SYN_ATT);
	ud_set_input_hook(&ud, get_next_insn_byte);

	child = fork();
	if (child == 0) {
		tracee(argc-1, argv+1);
	} else {
		return tracer(&ud);
	}
}
