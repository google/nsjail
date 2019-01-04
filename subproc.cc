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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "cgroup.h"
#include "contain.h"
#include "logs.h"
#include "macros.h"
#include "net.h"
#include "sandbox.h"
#include "user.h"
#include "util.h"

namespace subproc {

#if !defined(CLONE_NEWCGROUP)
#define CLONE_NEWCGROUP 0x02000000
#endif /* !defined(CLONE_NEWCGROUP) */

static const std::string cloneFlagsToStr(uintptr_t flags) {
	std::string res;

	struct {
		const uintptr_t flag;
		const char* const name;
	} static const cloneFlags[] = {
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

	uintptr_t knownFlagMask = CSIGNAL;
	for (const auto& i : cloneFlags) {
		if (flags & i.flag) {
			res.append(i.name).append("|");
		}
		knownFlagMask |= i.flag;
	}

	if (flags & ~(knownFlagMask)) {
		util::StrAppend(&res, "%#tx|", flags & ~(knownFlagMask));
	}
	res.append(util::sigName(flags & CSIGNAL).c_str());
	return res;
}

/* Reset the execution environment for the new process */
static bool resetEnv(void) {
	/* Set all previously changed signals to their default behavior */
	for (const auto& sig : nssigs) {
		if (signal(sig, SIG_DFL) == SIG_ERR) {
			PLOG_W("signal(%s, SIG_DFL)", util::sigName(sig).c_str());
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

static const char kSubprocDoneChar = 'D';
static const char kSubprocErrorChar = 'E';

static void subprocNewProc(nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err, int pipefd) {
	if (!contain::setupFD(nsjconf, fd_in, fd_out, fd_err)) {
		return;
	}
	if (!resetEnv()) {
		return;
	}

	if (pipefd == -1) {
		if (!user::initNsFromParent(nsjconf, getpid())) {
			LOG_E("Couldn't initialize net user namespace");
			return;
		}
		if (!cgroup::initNsFromParent(nsjconf, getpid())) {
			LOG_E("Couldn't initialize net user namespace");
			return;
		}
	} else {
		char doneChar;
		if (util::readFromFd(pipefd, &doneChar, sizeof(doneChar)) != sizeof(doneChar)) {
			return;
		}
		if (doneChar != kSubprocDoneChar) {
			return;
		}
	}
	if (!contain::containProc(nsjconf)) {
		return;
	}
	if (!nsjconf->keep_env) {
		clearenv();
	}
	for (const auto& env : nsjconf->envs) {
		putenv(const_cast<char*>(env.c_str()));
	}

	auto connstr = net::connToText(fd_in, /* remote= */ true, NULL);
	LOG_I("Executing '%s' for '%s'", nsjconf->exec_file.c_str(), connstr.c_str());

	std::vector<const char*> argv;
	for (const auto& s : nsjconf->argv) {
		argv.push_back(s.c_str());
		LOG_D(" Arg: '%s'", s.c_str());
	}
	argv.push_back(nullptr);

	/* Should be the last one in the sequence */
	if (!sandbox::applyPolicy(nsjconf)) {
		return;
	}

	if (nsjconf->use_execveat) {
#if defined(__NR_execveat)
		syscall(__NR_execveat, (uintptr_t)nsjconf->exec_fd, "", (char* const*)argv.data(),
		    environ, (uintptr_t)AT_EMPTY_PATH);
#else  /* defined(__NR_execveat) */
		LOG_E("Your system doesn't support execveat() syscall");
		return;
#endif /* defined(__NR_execveat) */
	} else {
		execv(nsjconf->exec_file.c_str(), (char* const*)argv.data());
	}

	PLOG_E("execve('%s') failed", nsjconf->exec_file.c_str());
}

static void addProc(nsjconf_t* nsjconf, pid_t pid, int sock) {
	pids_t p;

	p.pid = pid;
	p.start = time(NULL);
	p.remote_txt = net::connToText(sock, /* remote= */ true, &p.remote_addr);

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "/proc/%d/syscall", (int)pid);
	p.pid_syscall_fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));

	nsjconf->pids.push_back(p);

	LOG_D("Added pid '%d' with start time '%u' to the queue for IP: '%s'", p.pid,
	    (unsigned int)p.start, p.remote_txt.c_str());
}

static void removeProc(nsjconf_t* nsjconf, pid_t pid) {
	for (auto p = nsjconf->pids.begin(); p != nsjconf->pids.end(); ++p) {
		if (p->pid == pid) {
			LOG_D("Removing pid '%d' from the queue (IP:'%s', start time:'%s')", p->pid,
			    p->remote_txt.c_str(), util::timeToStr(p->start).c_str());
			close(p->pid_syscall_fd);
			nsjconf->pids.erase(p);

			return;
		}
	}
	LOG_W("PID: %d not found (?)", pid);
}

int countProc(nsjconf_t* nsjconf) {
	return nsjconf->pids.size();
}

void displayProc(nsjconf_t* nsjconf) {
	LOG_I("Total number of spawned namespaces: %d", countProc(nsjconf));
	time_t now = time(NULL);
	for (const auto& pid : nsjconf->pids) {
		time_t diff = now - pid.start;
		uint64_t left = nsjconf->tlimit ? nsjconf->tlimit - (uint64_t)diff : 0;
		LOG_I("PID: %d, Remote host: %s, Run time: %ld sec. (time left: %" PRId64 " sec.)",
		    pid.pid, pid.remote_txt.c_str(), (long)diff, left);
	}
}

static const pids_t* getPidElem(nsjconf_t* nsjconf, pid_t pid) {
	for (const auto& p : nsjconf->pids) {
		if (p.pid == pid) {
			return &p;
		}
	}
	return NULL;
}

static void seccompViolation(nsjconf_t* nsjconf, siginfo_t* si) {
	LOG_W("PID: %d commited a syscall/seccomp violation and exited with SIGSYS", si->si_pid);

	const pids_t* p = getPidElem(nsjconf, si->si_pid);
	if (p == NULL) {
		LOG_W("PID:%d SiSyscall: %d, SiCode: %d, SiErrno: %d, SiSigno: %d", (int)si->si_pid,
		    si->si_syscall, si->si_code, si->si_errno, si->si_signo);
		LOG_E("Couldn't find pid element in the subproc list for PID: %d", (int)si->si_pid);
		return;
	}

	char buf[4096];
	ssize_t rdsize = util::readFromFd(p->pid_syscall_fd, buf, sizeof(buf) - 1);
	if (rdsize < 1) {
		LOG_W("PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d, SiSigno: %d",
		    (int)si->si_pid, si->si_syscall, si->si_code, si->si_errno, si->si_signo);
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
		LOG_W(
		    "PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d, SiSigno: %d, SP: %#tx, PC: "
		    "%#tx",
		    (int)si->si_pid, si->si_syscall, si->si_code, si->si_errno, si->si_signo, arg1,
		    arg2);
	} else {
		LOG_W("PID: %d, SiSyscall: %d, SiCode: %d, SiErrno: %d, Syscall string '%s'",
		    (int)si->si_pid, si->si_syscall, si->si_code, si->si_errno, buf);
	}
}

static int reapProc(nsjconf_t* nsjconf, pid_t pid, bool should_wait = false) {
	int status;

	if (wait4(pid, &status, should_wait ? 0 : WNOHANG, NULL) == pid) {
		cgroup::finishFromParent(nsjconf, pid);

		std::string remote_txt = "[UNKNOWN]";
		const pids_t* elem = getPidElem(nsjconf, pid);
		if (elem) {
			remote_txt = elem->remote_txt;
		}

		if (WIFEXITED(status)) {
			LOG_I("PID: %d (%s) exited with status: %d, (PIDs left: %d)", pid,
			    remote_txt.c_str(), WEXITSTATUS(status), countProc(nsjconf) - 1);
			removeProc(nsjconf, pid);
			return WEXITSTATUS(status);
		}
		if (WIFSIGNALED(status)) {
			LOG_I("PID: %d (%s) terminated with signal: %s (%d), (PIDs left: %d)", pid,
			    remote_txt.c_str(), util::sigName(WTERMSIG(status)).c_str(),
			    WTERMSIG(status), countProc(nsjconf) - 1);
			removeProc(nsjconf, pid);
			return 128 + WTERMSIG(status);
		}
	}
	return 0;
}

int reapProc(nsjconf_t* nsjconf) {
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
		rv = reapProc(nsjconf, si.si_pid);
	}

	time_t now = time(NULL);
	for (const auto& p : nsjconf->pids) {
		if (nsjconf->tlimit == 0) {
			continue;
		}
		pid_t pid = p.pid;
		time_t diff = now - p.start;
		if ((uint64_t)diff >= nsjconf->tlimit) {
			LOG_I("PID: %d run time >= time limit (%ld >= %" PRIu64
			      ") (%s). Killing it",
			    pid, (long)diff, nsjconf->tlimit, p.remote_txt.c_str());
			/*
			 * Probably a kernel bug - some processes cannot be killed with KILL if
			 * they're namespaced, and in a stopped state
			 */
			kill(pid, SIGCONT);
			LOG_D("Sent SIGCONT to PID: %d", pid);
			kill(pid, SIGKILL);
			LOG_D("Sent SIGKILL to PID: %d", pid);
		}
	}
	return rv;
}

void killAndReapAll(nsjconf_t* nsjconf) {
	while (!nsjconf->pids.empty()) {
		pid_t pid = nsjconf->pids.front().pid;
		if (kill(pid, SIGKILL) == 0) {
			reapProc(nsjconf, pid, true);
		} else {
			removeProc(nsjconf, pid);
		}
	}
}

static bool initParent(nsjconf_t* nsjconf, pid_t pid, int pipefd) {
	if (!net::initNsFromParent(nsjconf, pid)) {
		LOG_E("Couldn't initialize net namespace for pid '%d'", pid);
		return false;
	}
	if (!cgroup::initNsFromParent(nsjconf, pid)) {
		LOG_E("Couldn't initialize cgroup user namespace for pid '%d'", pid);
		exit(0xff);
	}
	if (!user::initNsFromParent(nsjconf, pid)) {
		LOG_E("Couldn't initialize user namespace for pid %d", pid);
		return false;
	}
	if (!util::writeToFd(pipefd, &kSubprocDoneChar, sizeof(kSubprocDoneChar))) {
		LOG_E("Couldn't signal the new process via a socketpair");
		return false;
	}
	return true;
}

bool runChild(nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err) {
	if (!net::limitConns(nsjconf, fd_in)) {
		return true;
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
		if (unshare(flags) == -1) {
			PLOG_F("unshare(%s)", cloneFlagsToStr(flags).c_str());
		}
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, -1);
		LOG_F("Launching new process failed");
	}

	flags |= SIGCHLD;
	LOG_D("Creating new process with clone flags:%s", cloneFlagsToStr(flags).c_str());

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
		PLOG_E("socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) failed");
		return false;
	}
	int child_fd = sv[0];
	int parent_fd = sv[1];

	pid_t pid = cloneProc(flags);
	if (pid == 0) {
		close(parent_fd);
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, child_fd);
		util::writeToFd(child_fd, &kSubprocErrorChar, sizeof(kSubprocErrorChar));
		LOG_F("Launching child process failed");
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
		    "your kernel with support for namespaces or check the current value of the "
		    "kernel.unprivileged_userns_clone sysctl",
		    cloneFlagsToStr(flags).c_str());
		close(parent_fd);
		return false;
	}
	addProc(nsjconf, pid, fd_in);

	if (!initParent(nsjconf, pid, parent_fd)) {
		close(parent_fd);
		return false;
	}

	char rcvChar;
	if (util::readFromFd(parent_fd, &rcvChar, sizeof(rcvChar)) == sizeof(rcvChar) &&
	    rcvChar == kSubprocErrorChar) {
		LOG_W("Received error message from the child process before it has been executed");
		close(parent_fd);
		return false;
	}

	close(parent_fd);
	return true;
}

/*
 * Will be used inside the child process only, so it's safe to have it in BSS.
 * Some CPU archs (e.g. aarch64) must have it aligned. Size: 128 KiB (/2)
 */
static uint8_t cloneStack[128 * 1024] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
/* Cannot be on the stack, as the child's stack pointer will change after clone() */
static __thread jmp_buf env;

static int cloneFunc(void* arg __attribute__((unused))) {
	longjmp(env, 1);
	return 0;
}

/*
 * Avoid problems with caching of PID/TID in glibc - when using syscall(__NR_clone) glibc doesn't
 * update the internal PID/TID caches, what can lead to invalid values being returned by getpid()
 * or incorrect PID/TIDs used in raise()/abort() functions
 */
pid_t cloneProc(uintptr_t flags) {
	if (flags & CLONE_VM) {
		LOG_E("Cannot use clone(flags & CLONE_VM)");
		return -1;
	}

	if (setjmp(env) == 0) {
		LOG_D("Cloning process with flags:%s", cloneFlagsToStr(flags).c_str());
		/*
		 * Avoid the problem of the stack growing up/down under different CPU architectures,
		 * by using middle of the static stack buffer (which is temporary, and used only
		 * inside of the cloneFunc()
		 */
		void* stack = &cloneStack[sizeof(cloneStack) / 2];
		/* Parent */
		return clone(cloneFunc, stack, flags, NULL, NULL, NULL);
	}
	/* Child */
	return 0;
}

int systemExe(const std::vector<std::string>& args, char** env) {
	bool exec_failed = false;

	std::vector<const char*> argv;
	for (const auto& a : args) {
		argv.push_back(a.c_str());
	}
	argv.push_back(nullptr);

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
		execve(argv[0], (char* const*)argv.data(), (char* const*)env);
		PLOG_W("execve('%s')", argv[0]);
		util::writeToFd(sv[1], "A", 1);
		exit(0);
	}

	close(sv[1]);
	char buf[1];
	if (util::readFromFd(sv[0], buf, sizeof(buf)) > 0) {
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
			    util::sigName(exit_signal).c_str());
			return 2;
		}
		LOG_W("Unknown exit status: %d", status);
	}
}

}  // namespace subproc
