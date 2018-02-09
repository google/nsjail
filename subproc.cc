/*

   nsjail - subprocess management
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "subproc.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cgroup.h"
#include "contain.h"
#include "net.h"
#include "sandbox.h"
#include "user.h"

extern "C" {
#include "common.h"
#include "log.h"
#include "util.h"

#if !defined(CLONE_NEWCGROUP)
#define CLONE_NEWCGROUP 0x02000000
#endif /* !defined(CLONE_NEWCGROUP) */

static const char* subprocCloneFlagsToStr(uintptr_t flags) {
	static __thread char cloneFlagName[1024];
	cloneFlagName[0] = '\0';

	static struct {
		const uintptr_t flag;
		const char* const name;
	} const cloneFlags[] = {
	    NS_VALSTR_STRUCT(CLONE_VM),
	    NS_VALSTR_STRUCT(CLONE_FS),
	    NS_VALSTR_STRUCT(CLONE_FILES),
	    NS_VALSTR_STRUCT(CLONE_SIGHAND),
	    NS_VALSTR_STRUCT(CLONE_PTRACE),
	    NS_VALSTR_STRUCT(CLONE_VFORK),
	    NS_VALSTR_STRUCT(CLONE_PARENT),
	    NS_VALSTR_STRUCT(CLONE_THREAD),
	    NS_VALSTR_STRUCT(CLONE_NEWNS),
	    NS_VALSTR_STRUCT(CLONE_SYSVSEM),
	    NS_VALSTR_STRUCT(CLONE_SETTLS),
	    NS_VALSTR_STRUCT(CLONE_PARENT_SETTID),
	    NS_VALSTR_STRUCT(CLONE_CHILD_CLEARTID),
	    NS_VALSTR_STRUCT(CLONE_DETACHED),
	    NS_VALSTR_STRUCT(CLONE_UNTRACED),
	    NS_VALSTR_STRUCT(CLONE_CHILD_SETTID),
	    NS_VALSTR_STRUCT(CLONE_NEWCGROUP),
	    NS_VALSTR_STRUCT(CLONE_NEWUTS),
	    NS_VALSTR_STRUCT(CLONE_NEWIPC),
	    NS_VALSTR_STRUCT(CLONE_NEWUSER),
	    NS_VALSTR_STRUCT(CLONE_NEWPID),
	    NS_VALSTR_STRUCT(CLONE_NEWNET),
	    NS_VALSTR_STRUCT(CLONE_IO),
	};

	for (size_t i = 0; i < ARRAYSIZE(cloneFlags); i++) {
		if (flags & cloneFlags[i].flag) {
			utilSSnPrintf(
			    cloneFlagName, sizeof(cloneFlagName), "%s|", cloneFlags[i].name);
		}
	}

	uintptr_t knownFlagMask = CSIGNAL;
	for (size_t i = 0; i < ARRAYSIZE(cloneFlags); i++) {
		knownFlagMask |= cloneFlags[i].flag;
	}
	if (flags & ~(knownFlagMask)) {
		utilSSnPrintf(
		    cloneFlagName, sizeof(cloneFlagName), "%#tx|", flags & ~(knownFlagMask));
	}
	utilSSnPrintf(cloneFlagName, sizeof(cloneFlagName), "%s", utilSigName(flags & CSIGNAL));
	return cloneFlagName;
}

}  // extern "C"

/* Reset the execution environment for the new process */
static bool resetEnv(void) {
	/* Set all previously changed signals to their default behavior */
	for (size_t i = 0; i < ARRAYSIZE(nssigs); i++) {
		if (signal(nssigs[i], SIG_DFL) == SIG_ERR) {
			PLOG_W("signal(%s, SIG_DFL)", utilSigName(nssigs[i]));
			return false;
		}
	}
	/* Unblock all signals */
	sigset_t sset;
	sigemptyset(&sset);
	if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
		PLOG_W("sigprocmask(SIG_SET, empty)");
		return false;
	}
	return true;
}

namespace subproc {

static const char kSubprocDoneChar = 'D';

static int subprocNewProc(
    struct nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err, int pipefd) {
	if (contain::setupFD(nsjconf, fd_in, fd_out, fd_err) == false) {
		_exit(0xff);
	}
	if (!resetEnv()) {
		_exit(0xff);
	}

	if (pipefd == -1) {
		if (user::initNsFromParent(nsjconf, getpid()) == false) {
			LOG_E("Couldn't initialize net user namespace");
			_exit(0xff);
		}
		if (cgroup::initNsFromParent(nsjconf, getpid()) == false) {
			LOG_E("Couldn't initialize net user namespace");
			_exit(0xff);
		}
	} else {
		char doneChar;
		if (utilReadFromFd(pipefd, &doneChar, sizeof(doneChar)) != sizeof(doneChar)) {
			_exit(0xff);
		}
		if (doneChar != kSubprocDoneChar) {
			_exit(0xff);
		}
	}
	if (contain::containProc(nsjconf) == false) {
		_exit(0xff);
	}
	if (nsjconf->keep_env == false) {
		clearenv();
	}
	struct charptr_t* p;
	TAILQ_FOREACH(p, &nsjconf->envs, pointers) { putenv((char*)p->val); }

	char cs_addr[64];
	net::connToText(fd_in, true /* remote */, cs_addr, sizeof(cs_addr), NULL);
	LOG_I("Executing '%s' for '%s'", nsjconf->exec_file, cs_addr);

	for (size_t i = 0; nsjconf->argv[i]; i++) {
		LOG_D(" Arg[%zu]: '%s'", i, nsjconf->argv[i]);
	}

	/* Should be the last one in the sequence */
	if (sandbox::applyPolicy(nsjconf) == false) {
		exit(0xff);
	}

	if (nsjconf->use_execveat) {
#if defined(__NR_execveat)
		syscall(__NR_execveat, (uintptr_t)nsjconf->exec_fd, "",
		    (char* const*)&nsjconf->argv[0], environ, (uintptr_t)AT_EMPTY_PATH);
#else  /* defined(__NR_execveat) */
		LOG_F("Your system doesn't support execveat() syscall");
#endif /* defined(__NR_execveat) */
	} else {
		execv(nsjconf->exec_file, (char* const*)&nsjconf->argv[0]);
	}

	PLOG_E("execve('%s') failed", nsjconf->exec_file);

	_exit(0xff);
}

static void addProc(struct nsjconf_t* nsjconf, pid_t pid, int sock) {
	struct pids_t* p = reinterpret_cast<struct pids_t*>(utilMalloc(sizeof(struct pids_t)));
	p->pid = pid;
	p->start = time(NULL);
	net::connToText(
	    sock, true /* remote */, p->remote_txt, sizeof(p->remote_txt), &p->remote_addr);

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "/proc/%d/syscall", (int)pid);
	p->pid_syscall_fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));

	TAILQ_INSERT_HEAD(&nsjconf->pids, p, pointers);

	LOG_D("Added pid '%d' with start time '%u' to the queue for IP: '%s'", pid,
	    (unsigned int)p->start, p->remote_txt);
}

static void removeProc(struct nsjconf_t* nsjconf, pid_t pid) {
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		if (p->pid == pid) {
			LOG_D("Removing pid '%d' from the queue (IP:'%s', start time:'%s')", p->pid,
			    p->remote_txt, utilTimeToStr(p->start));
			close(p->pid_syscall_fd);
			TAILQ_REMOVE(&nsjconf->pids, p, pointers);
			free(p);
			return;
		}
	}
	LOG_W("PID: %d not found (?)", pid);
}

int countProc(struct nsjconf_t* nsjconf) {
	int cnt = 0;
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) { cnt++; }
	return cnt;
}

void displayProc(struct nsjconf_t* nsjconf) {
	LOG_I("Total number of spawned namespaces: %d", countProc(nsjconf));
	time_t now = time(NULL);
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		time_t diff = now - p->start;
		time_t left = nsjconf->tlimit ? nsjconf->tlimit - diff : 0;
		LOG_I("PID: %d, Remote host: %s, Run time: %ld sec. (time left: %ld sec.)", p->pid,
		    p->remote_txt, (long)diff, (long)left);
	}
}

static struct pids_t* getPidElem(struct nsjconf_t* nsjconf, pid_t pid) {
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		if (p->pid == pid) {
			return p;
		}
	}
	return NULL;
}

static void seccompViolation(struct nsjconf_t* nsjconf, siginfo_t* si) {
	LOG_W("PID: %d commited a syscall/seccomp violation and exited with SIGSYS", si->si_pid);

	struct pids_t* p = getPidElem(nsjconf, si->si_pid);
	if (p == NULL) {
		LOG_W("PID:%d SiSyscall: %d, SiCode: %d, SiErrno: %d", (int)si->si_pid,
		    si->si_syscall, si->si_code, si->si_errno);
		LOG_E("Couldn't find pid element in the subproc list for PID: %d", (int)si->si_pid);
		return;
	}

	char buf[4096];
	ssize_t rdsize = utilReadFromFd(p->pid_syscall_fd, buf, sizeof(buf) - 1);
	if (rdsize < 1) {
		LOG_W("PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d", (int)si->si_pid,
		    si->si_syscall, si->si_code, si->si_errno);
		return;
	}
	buf[rdsize - 1] = '\0';

	uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, sp, pc;
	ptrdiff_t sc;
	int ret = sscanf(buf, "%td %tx %tx %tx %tx %tx %tx %tx %tx", &sc, &arg1, &arg2, &arg3,
	    &arg4, &arg5, &arg6, &sp, &pc);
	if (ret == 9) {
		LOG_W(
		    "PID: %d, Syscall number: %td, Arguments: %#tx, %#tx, %#tx, %#tx, %#tx, %#tx, "
		    "SP: %#tx, PC: %#tx, si_syscall: %d, si_errno: %#x",
		    (int)si->si_pid, sc, arg1, arg2, arg3, arg4, arg5, arg6, sp, pc, si->si_syscall,
		    si->si_errno);
	} else if (ret == 3) {
		LOG_W("PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d, SP: %#tx, PC: %#tx",
		    (int)si->si_pid, si->si_syscall, si->si_code, si->si_errno, arg1, arg2);
	} else {
		LOG_W("PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d, Syscall string '%s'",
		    (int)si->si_pid, si->si_syscall, si->si_code, si->si_errno, buf);
	}
}

int reapProc(struct nsjconf_t* nsjconf) {
	int status;
	int rv = 0;
	siginfo_t si;

	for (;;) {
		si.si_pid = 0;
		if (waitid(P_ALL, 0, &si, WNOHANG | WNOWAIT | WEXITED) == -1) {
			break;
		}
		if (si.si_pid == 0) {
			break;
		}
		if (si.si_code == CLD_KILLED && si.si_status == SIGSYS) {
			seccompViolation(nsjconf, &si);
		}

		if (wait4(si.si_pid, &status, WNOHANG, NULL) == si.si_pid) {
			cgroup::finishFromParent(nsjconf, si.si_pid);

			const char* remote_txt = "[UNKNOWN]";
			struct pids_t* elem = getPidElem(nsjconf, si.si_pid);
			if (elem) {
				remote_txt = elem->remote_txt;
			}

			if (WIFEXITED(status)) {
				LOG_I("PID: %d (%s) exited with status: %d, (PIDs left: %d)",
				    si.si_pid, remote_txt, WEXITSTATUS(status),
				    countProc(nsjconf) - 1);
				removeProc(nsjconf, si.si_pid);
				rv = WEXITSTATUS(status) % 100;
				if (rv == 0 && WEXITSTATUS(status) != 0) {
					rv = 1;
				}
			}
			if (WIFSIGNALED(status)) {
				LOG_I(
				    "PID: %d (%s) terminated with signal: %s (%d), (PIDs left: %d)",
				    si.si_pid, remote_txt, utilSigName(WTERMSIG(status)),
				    WTERMSIG(status), countProc(nsjconf) - 1);
				removeProc(nsjconf, si.si_pid);
				rv = 100 + WTERMSIG(status);
			}
		}
	}

	time_t now = time(NULL);
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		if (nsjconf->tlimit == 0) {
			continue;
		}
		pid_t pid = p->pid;
		time_t diff = now - p->start;
		if (diff >= nsjconf->tlimit) {
			LOG_I("PID: %d run time >= time limit (%ld >= %ld) (%s). Killing it", pid,
			    (long)diff, (long)nsjconf->tlimit, p->remote_txt);
			/*
			 * Probably a kernel bug - some processes cannot be killed with KILL if
			 * they're namespaced, and in a stopped state
			 */
			kill(pid, SIGCONT);
			PLOG_D("Sent SIGCONT to PID: %d", pid);
			kill(pid, SIGKILL);
			PLOG_D("Sent SIGKILL to PID: %d", pid);
		}
	}
	return rv;
}

void killAll(struct nsjconf_t* nsjconf) {
	struct pids_t* p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) { kill(p->pid, SIGKILL); }
}

static bool initParent(struct nsjconf_t* nsjconf, pid_t pid, int pipefd) {
	if (net::initNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't create and put MACVTAP interface into NS of PID '%d'", pid);
		return false;
	}
	if (cgroup::initNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't initialize cgroup user namespace");
		exit(0xff);
	}
	if (user::initNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't initialize user namespaces for pid %d", pid);
		return false;
	}
	if (utilWriteToFd(pipefd, &kSubprocDoneChar, sizeof(kSubprocDoneChar)) !=
	    sizeof(kSubprocDoneChar)) {
		LOG_E("Couldn't signal the new process via a socketpair");
		return false;
	}
	return true;
}

void runChild(struct nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err) {
	if (net::limitConns(nsjconf, fd_in) == false) {
		return;
	}
	unsigned long flags = 0UL;
	flags |= (nsjconf->clone_newnet ? CLONE_NEWNET : 0);
	flags |= (nsjconf->clone_newuser ? CLONE_NEWUSER : 0);
	flags |= (nsjconf->clone_newns ? CLONE_NEWNS : 0);
	flags |= (nsjconf->clone_newpid ? CLONE_NEWPID : 0);
	flags |= (nsjconf->clone_newipc ? CLONE_NEWIPC : 0);
	flags |= (nsjconf->clone_newuts ? CLONE_NEWUTS : 0);
	flags |= (nsjconf->clone_newcgroup ? CLONE_NEWCGROUP : 0);

	if (nsjconf->mode == MODE_STANDALONE_EXECVE) {
		LOG_D("Entering namespace with flags:%s", subprocCloneFlagsToStr(flags));
		if (unshare(flags) == -1) {
			PLOG_E("unshare(%s)", subprocCloneFlagsToStr(flags));
			_exit(0xff);
		}
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, -1);
	}

	flags |= SIGCHLD;
	LOG_D("Creating new process with clone flags:%s", subprocCloneFlagsToStr(flags));

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
		PLOG_E("socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) failed");
		return;
	}
	int child_fd = sv[0];
	int parent_fd = sv[1];

	pid_t pid = subprocClone(flags);
	if (pid == 0) {
		close(parent_fd);
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, child_fd);
	}
	close(child_fd);
	if (pid == -1) {
		if (flags & CLONE_NEWCGROUP) {
			PLOG_E(
			    "nsjail tried to use the CLONE_NEWCGROUP clone flag, which is "
			    "supported under kernel versions >= 4.6 only. Try disabling this flag");
		}
		PLOG_E(
		    "clone(flags=%s) failed. You probably need root privileges if your system "
		    "doesn't support CLONE_NEWUSER. Alternatively, you might want to recompile "
		    "your kernel with support for namespaces or check the setting of the "
		    "kernel.unprivileged_userns_clone sysctl",
		    subprocCloneFlagsToStr(flags));
		close(parent_fd);
		return;
	}
	addProc(nsjconf, pid, fd_in);

	if (initParent(nsjconf, pid, parent_fd) == false) {
		close(parent_fd);
		return;
	}

	close(parent_fd);
	char cs_addr[64];
	net::connToText(fd_in, true /* remote */, cs_addr, sizeof(cs_addr), NULL);
}

}  // namespace subproc

/*
 * Will be used inside the child process only, so it's safe to have it in BSS.
 * Some CPU archs (e.g. aarch64) must have it aligned. Size: 128 KiB (/2)
 */
static uint8_t subprocCloneStack[128 * 1024] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
/* Cannot be on the stack, as the child's stack pointer will change after clone() */
static __thread jmp_buf env;

static int subprocCloneFunc(void* arg __attribute__((unused))) {
	longjmp(env, 1);
	return 0;
}

/*
 * Avoid problems with caching of PID/TID in glibc - when using syscall(__NR_clone) glibc doesn't
 * update the internal PID/TID caches, what can lead to invalid values being returned by getpid()
 * or incorrect PID/TIDs used in raise()/abort() functions
 */
pid_t subprocClone(uintptr_t flags) {
	if (flags & CLONE_VM) {
		LOG_E("Cannot use clone(flags & CLONE_VM)");
		return -1;
	}

	if (setjmp(env) == 0) {
		LOG_D("Cloning process with flags:%s", subprocCloneFlagsToStr(flags));
		/*
		 * Avoid the problem of the stack growing up/down under different CPU architectures,
		 * by using middle of the static stack buffer (which is temporary, and used only
		 * inside of the subprocCloneFunc()
		 */
		void* stack = &subprocCloneStack[sizeof(subprocCloneStack) / 2];
		/* Parent */
		return clone(subprocCloneFunc, stack, flags, NULL, NULL, NULL);
	}
	/* Child */
	return 0;
}

int subprocSystem(const char** argv, char** env) {
	bool exec_failed = false;

	int sv[2];
	if (pipe2(sv, O_CLOEXEC) == -1) {
		PLOG_W("pipe2(sv, O_CLOEXEC");
		return -1;
	}

	pid_t pid = fork();
	if (pid == -1) {
		PLOG_W("fork()");
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (pid == 0) {
		close(sv[0]);
		execve(argv[0], (char* const*)argv, (char* const*)env);
		PLOG_W("execve('%s')", argv[0]);
		utilWriteToFd(sv[1], "A", 1);
		exit(0);
	}

	close(sv[1]);
	char buf[1];
	if (utilReadFromFd(sv[0], buf, sizeof(buf)) > 0) {
		exec_failed = true;
		LOG_W("Couldn't execute '%s'", argv[0]);
	}
	close(sv[0]);

	for (;;) {
		int status;
		int ret = wait4(pid, &status, __WALL, NULL);
		if (ret == -1 && errno == EINTR) {
			continue;
		}
		if (ret == -1) {
			PLOG_W("wait4(pid=%d)", pid);
			return -1;
		}
		if (WIFEXITED(status)) {
			int exit_code = WEXITSTATUS(status);
			LOG_D("PID %d exited with exit code: %d", pid, exit_code);
			if (exec_failed) {
				return -1;
			} else if (exit_code == 0) {
				return 0;
			} else {
				return 1;
			}
		}
		if (WIFSIGNALED(status)) {
			int exit_signal = WTERMSIG(status);
			LOG_W("PID %d killed by signal: %d (%s)", pid, exit_signal,
			    utilSigName(exit_signal));
			return 2;
		}
		LOG_W("Unknown exit status: %d", status);
	}
}
