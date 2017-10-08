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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cgroup.h"
#include "common.h"
#include "contain.h"
#include "log.h"
#include "net.h"
#include "sandbox.h"
#include "user.h"
#include "util.h"

static const char subprocDoneChar = 'D';

#define VALSTR_STRUCT(x) \
    {                    \
        x, #x            \
    }

#if !defined(CLONE_NEWCGROUP)
#define CLONE_NEWCGROUP 0x02000000
#endif				/* !defined(CLONE_NEWCGROUP) */

static const char *subprocCloneFlagsToStr(uintptr_t flags)
{
	static __thread char cloneFlagName[1024];
	cloneFlagName[0] = '\0';

    /*  *INDENT-OFF* */
    static struct {
        const uintptr_t flag;
        const char* const name;
    } const cloneFlags[] = {
        VALSTR_STRUCT(CLONE_VM),
        VALSTR_STRUCT(CLONE_FS),
        VALSTR_STRUCT(CLONE_FILES),
        VALSTR_STRUCT(CLONE_SIGHAND),
        VALSTR_STRUCT(CLONE_PTRACE),
        VALSTR_STRUCT(CLONE_VFORK),
        VALSTR_STRUCT(CLONE_PARENT),
        VALSTR_STRUCT(CLONE_THREAD),
        VALSTR_STRUCT(CLONE_NEWNS),
        VALSTR_STRUCT(CLONE_SYSVSEM),
        VALSTR_STRUCT(CLONE_SETTLS),
        VALSTR_STRUCT(CLONE_PARENT_SETTID),
        VALSTR_STRUCT(CLONE_CHILD_CLEARTID),
        VALSTR_STRUCT(CLONE_DETACHED),
        VALSTR_STRUCT(CLONE_UNTRACED),
        VALSTR_STRUCT(CLONE_CHILD_SETTID),
        VALSTR_STRUCT(CLONE_NEWCGROUP),
        VALSTR_STRUCT(CLONE_NEWUTS),
        VALSTR_STRUCT(CLONE_NEWIPC),
        VALSTR_STRUCT(CLONE_NEWUSER),
        VALSTR_STRUCT(CLONE_NEWPID),
        VALSTR_STRUCT(CLONE_NEWNET),
        VALSTR_STRUCT(CLONE_IO),
    };
    /*  *INDENT-ON* */

	for (size_t i = 0; i < ARRAYSIZE(cloneFlags); i++) {
		if (flags & cloneFlags[i].flag) {
			utilSSnPrintf(cloneFlagName, sizeof(cloneFlagName), "%s|",
				      cloneFlags[i].name);
		}
	}

	uintptr_t knownFlagMask = CSIGNAL;
	for (size_t i = 0; i < ARRAYSIZE(cloneFlags); i++) {
		knownFlagMask |= cloneFlags[i].flag;
	}
	if (flags & ~(knownFlagMask)) {
		utilSSnPrintf(cloneFlagName, sizeof(cloneFlagName), "%#tx|",
			      flags & ~(knownFlagMask));
	}
	utilSSnPrintf(cloneFlagName, sizeof(cloneFlagName), "%s", utilSigName(flags & CSIGNAL));
	return cloneFlagName;
}

static int subprocNewProc(struct nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err, int pipefd)
{
	if (containSetupFD(nsjconf, fd_in, fd_out, fd_err) == false) {
		exit(0xff);
	}

	if (pipefd == -1) {
		if (userInitNsFromParent(nsjconf, getpid()) == false) {
			LOG_E("Couldn't initialize net user namespace");
			exit(0xff);
		}
		if (cgroupInitNsFromParent(nsjconf, getpid()) == false) {
			LOG_E("Couldn't initialize net user namespace");
			exit(0xff);
		}
	} else {
		char doneChar;
		if (utilReadFromFd(pipefd, &doneChar, sizeof(doneChar)) != sizeof(doneChar)) {
			exit(0xff);
		}
		if (doneChar != subprocDoneChar) {
			exit(0xff);
		}
	}
	if (containContain(nsjconf) == false) {
		exit(0xff);
	}
	if (nsjconf->keep_env == false) {
		clearenv();
	}
	struct charptr_t *p;
	TAILQ_FOREACH(p, &nsjconf->envs, pointers) {
		putenv((char *)p->val);
	}

	char cs_addr[64];
	netConnToText(fd_in, true /* remote */ , cs_addr, sizeof(cs_addr), NULL);
	LOG_I("Executing '%s' for '%s'", nsjconf->exec_file, cs_addr);

	for (size_t i = 0; nsjconf->argv[i]; i++) {
		LOG_D(" Arg[%zu]: '%s'", i, nsjconf->argv[i]);
	}

	/* Should be the last one in the sequence */
	if (sandboxApply(nsjconf) == false) {
		exit(0xff);
	}
	execv(nsjconf->exec_file, (char *const *)&nsjconf->argv[0]);

	PLOG_E("execve('%s') failed", nsjconf->exec_file);

	_exit(0xff);
}

static void subprocAdd(struct nsjconf_t *nsjconf, pid_t pid, int sock)
{
	struct pids_t *p = utilMalloc(sizeof(struct pids_t));
	p->pid = pid;
	p->start = time(NULL);
	netConnToText(sock, true /* remote */ , p->remote_txt, sizeof(p->remote_txt),
		      &p->remote_addr);

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "/proc/%d/syscall", (int)pid);
	p->pid_syscall_fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));

	TAILQ_INSERT_HEAD(&nsjconf->pids, p, pointers);

	LOG_D("Added pid '%d' with start time '%u' to the queue for IP: '%s'", pid,
	      (unsigned int)p->start, p->remote_txt);
}

static void subprocRemove(struct nsjconf_t *nsjconf, pid_t pid)
{
	struct pids_t *p;
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

int subprocCount(struct nsjconf_t *nsjconf)
{
	int cnt = 0;
	struct pids_t *p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		cnt++;
	}
	return cnt;
}

void subprocDisplay(struct nsjconf_t *nsjconf)
{
	LOG_I("Total number of spawned namespaces: %d", subprocCount(nsjconf));
	time_t now = time(NULL);
	struct pids_t *p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		time_t diff = now - p->start;
		time_t left = nsjconf->tlimit ? nsjconf->tlimit - diff : 0;
		LOG_I("PID: %d, Remote host: %s, Run time: %ld sec. (time left: %ld sec.)", p->pid,
		      p->remote_txt, (long)diff, (long)left);
	}
}

static struct pids_t *subprocGetPidElem(struct nsjconf_t *nsjconf, pid_t pid)
{
	struct pids_t *p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		if (p->pid == pid) {
			return p;
		}
	}
	return NULL;
}

static void subprocSeccompViolation(struct nsjconf_t *nsjconf, siginfo_t * si)
{
	LOG_W("PID: %d commited syscall/seccomp violation and exited with SIGSYS", si->si_pid);

	struct pids_t *p = subprocGetPidElem(nsjconf, si->si_pid);
	if (p == NULL) {
		LOG_E("Couldn't find pid element in the subproc list for PID: %d", (int)si->si_pid);
		return;
	}

	char buf[4096];
	ssize_t rdsize = utilReadFromFd(p->pid_syscall_fd, buf, sizeof(buf) - 1);
	if (rdsize < 1) {
		return;
	}
	buf[rdsize - 1] = '\0';

	uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, sp, pc;
	ptrdiff_t sc;
	int ret =
	    sscanf(buf, "%td %tx %tx %tx %tx %tx %tx %tx %tx", &sc, &arg1, &arg2, &arg3, &arg4,
		   &arg5, &arg6, &sp, &pc);
	if (ret == 9) {
		LOG_W
		    ("PID: %d, Syscall number: %td, Arguments: %#tx, %#tx, %#tx, %#tx, %#tx, %#tx, SP: %#tx, PC: %#tx, SI_SYSCALL: %#x",
		     (int)si->si_pid, sc, arg1, arg2, arg3, arg4, arg5, arg6, sp, pc,
		     si->si_syscall);
	} else if (ret == 3) {
		LOG_W("PID: %d, Syscall number: %#x, SP: %#tx, PC: %#tx", si->si_syscall,
		      (int)si->si_pid, arg1, arg2);
	} else {
		LOG_W("PID: %d, Syscall number: %#x, Syscall string '%s'", si->si_syscall,
		      (int)si->si_pid, buf);
	}
}

int subprocReap(struct nsjconf_t *nsjconf)
{
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
			subprocSeccompViolation(nsjconf, &si);
		}

		if (wait4(si.si_pid, &status, WNOHANG, NULL) == si.si_pid) {
			cgroupFinishFromParent(nsjconf, si.si_pid);

			const char *remote_txt = "[UNKNOWN]";
			struct pids_t *elem = subprocGetPidElem(nsjconf, si.si_pid);
			if (elem) {
				remote_txt = elem->remote_txt;
			}

			if (WIFEXITED(status)) {
				LOG_I("PID: %d (%s) exited with status: %d, (PIDs left: %d)",
				      si.si_pid, remote_txt, WEXITSTATUS(status),
				      subprocCount(nsjconf) - 1);
				subprocRemove(nsjconf, si.si_pid);
				rv = WEXITSTATUS(status) % 100;
				if (rv == 0 && WEXITSTATUS(status) != 0) {
					rv = 1;
				}
			}
			if (WIFSIGNALED(status)) {
				LOG_I
				    ("PID: %d (%s) terminated with signal: %s (%d), (PIDs left: %d)",
				     si.si_pid, remote_txt, utilSigName(WTERMSIG(status)),
				     WTERMSIG(status), subprocCount(nsjconf) - 1);
				subprocRemove(nsjconf, si.si_pid);
				rv = 100 + WTERMSIG(status);
			}
		}
	}

	time_t now = time(NULL);
	struct pids_t *p;
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

void subprocKillAll(struct nsjconf_t *nsjconf)
{
	struct pids_t *p;
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
		kill(p->pid, SIGKILL);
	}
}

static bool subprocInitParent(struct nsjconf_t *nsjconf, pid_t pid, int pipefd)
{
	if (netInitNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't create and put MACVTAP interface into NS of PID '%d'", pid);
		return false;
	}
	if (cgroupInitNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't initialize cgroup user namespace");
		exit(0xff);
	}
	if (userInitNsFromParent(nsjconf, pid) == false) {
		LOG_E("Couldn't initialize user namespaces for pid %d", pid);
		return false;
	}
	if (utilWriteToFd(pipefd, &subprocDoneChar, sizeof(subprocDoneChar)) !=
	    sizeof(subprocDoneChar)) {
		LOG_E("Couldn't signal the new process via a socketpair");
		return false;
	}
	return true;
}

/* Will be used inside the child process only, so it's save to have it in BSS */
static uint8_t subprocCloneStack[128 * 1024];	/* 128 KiB */
/* Cannot be on the stack, as the child's stack pointer will change after clone() */
static __thread jmp_buf env;

static int subprocCloneFunc(void *arg __attribute__ ((unused)))
{
	longjmp(env, 1);
	return 0;
}

/*
 * Avoid problems with caching of PID/TID in glibc - when using syscall(__NR_clone) glibc doesn't
 * not update internal PID/TID caches, which can lead to invalid values returned by getpid(),
 * or wrong PID/TIDs being used in raise()/abort() functions
 */
pid_t subprocClone(uintptr_t flags)
{
	if (flags & CLONE_VM) {
		LOG_E("Cannot use clone(flags & CLONE_VM)");
		return -1;
	}

	if (setjmp(env) == 0) {
		LOG_D("Cloning process with flags:%s", subprocCloneFlagsToStr(flags));
		/*
		 * Avoid the problem of the stack growing up/down under different CPU architectures, by using
		 * middle of the static stack buffer (which is temporary, and used only inside of subprocCloneFunc
		 */
		void *stack = &subprocCloneStack[sizeof(subprocCloneStack) / 2];
		/* Parent */
		return clone(subprocCloneFunc, stack, flags, NULL, NULL, NULL);
	}
	/* Child */
	return 0;
}

void subprocRunChild(struct nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err)
{
	if (netLimitConns(nsjconf, fd_in) == false) {
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
			PLOG_E("unshare(%#lx)", flags);
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
		PLOG_E("clone(flags=%s) failed. You probably need root privileges if your system "
		       "doesn't support CLONE_NEWUSER. Alternatively, you might want to recompile your "
		       "kernel with support for namespaces or check the setting of the "
		       "kernel.unprivileged_userns_clone sysctl", subprocCloneFlagsToStr(flags));
		close(parent_fd);
		return;
	}
	subprocAdd(nsjconf, pid, fd_in);

	if (subprocInitParent(nsjconf, pid, parent_fd) == false) {
		close(parent_fd);
		return;
	}

	close(parent_fd);
	char cs_addr[64];
	netConnToText(fd_in, true /* remote */ , cs_addr, sizeof(cs_addr), NULL);
}

int subprocSystem(const char **argv, char **env)
{
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
		execve(argv[0], (char *const *)argv, (char *const *)env);
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
			if (exec_failed == true) {
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
