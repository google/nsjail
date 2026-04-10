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
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <thread>
#include <vector>

#include "cgroup.h"
#include "cgroup2.h"
#include "contain.h"
#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "monitor.h"
#include "net.h"
#include "nstun/nstun.h"
#include "sandbox.h"
#include "user.h"
#include "util.h"

namespace subproc {

static std::string cloneFlagsToStr(uint64_t flags) {
	std::string res;

	struct {
		const uint64_t flag;
		const char* const name;
	} static const cloneFlags[] = {
	    NS_VALSTR_STRUCT(CLONE_NEWTIME),
	    NS_VALSTR_STRUCT(CLONE_VM),
	    NS_VALSTR_STRUCT(CLONE_FS),
	    NS_VALSTR_STRUCT(CLONE_FILES),
	    NS_VALSTR_STRUCT(CLONE_SIGHAND),

	    NS_VALSTR_STRUCT(CLONE_PIDFD),
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

	    NS_VALSTR_STRUCT(CLONE_CLEAR_SIGHAND),

	    NS_VALSTR_STRUCT(CLONE_INTO_CGROUP),
	};

	uint64_t knownFlagMask = 0;
	for (const auto& i : cloneFlags) {
		if (flags & i.flag) {
			if (!res.empty()) {
				res.append("|");
			}
			res.append(i.name);
		}
		knownFlagMask |= i.flag;
	}

	if (flags & ~(knownFlagMask)) {
		util::StrAppend(&res, "|%#" PRIx64, flags & ~(knownFlagMask));
	}
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
	if (sigprocmask(SIG_SETMASK, &sset, nullptr) == -1) {
		PLOG_W("sigprocmask(SIG_SET, empty)");
		return false;
	}
	return true;
}

static std::string concatArgs(const std::vector<const char*>& argv) {
	std::string ret;
	for (const auto& s : argv) {
		if (s) {
			if (!ret.empty()) {
				ret.append(", ");
			}
			ret.append(util::StrQuote(s));
		}
	}
	return ret;
}

static void newProc(nsj_t* nsj, int netfd, int fd_in, int fd_out, int fd_err, int ipc_fd) {
	auto connstr = net::connToText(netfd, /* remote= */ true, nullptr);

	/*
	 * Set parent death signal early to prevent the child from hanging
	 * if the parent dies during the IPC handshake or setup.
	 */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
		PLOG_W("prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
	}

	if (nsj->njc.has_oom_score_adj()) {
		std::string score = std::to_string(nsj->njc.oom_score_adj());
		if (!util::writeBufToFile(
			"/proc/self/oom_score_adj", score.c_str(), score.length(), O_WRONLY)) {
			LOG_W("Couldn't set /proc/self/oom_score_adj to '%s'", score.c_str());
		}
	}

	if (!contain::setupFD(nsj, fd_in, fd_out, fd_err, ipc_fd)) {
		return;
	}
	if (!resetEnv()) {
		return;
	}

	if (ipc_fd == -1) {
		if (!user::initNsFromParent(nsj, getpid())) {
			LOG_E("Couldn't initialize user namespace");
			return;
		}
		if (nsj->njc.use_cgroupv2()) {
			if (!cgroup2::initNsFromParent(nsj, getpid())) {
				LOG_E("Couldn't initialize cgroup v2 namespace");
				return;
			}
		} else if (!cgroup::initNsFromParent(nsj, getpid())) {
			LOG_E("Couldn't initialize cgroup namespace");
			return;
		}
	} else {
		if (!net::initChildPreSync(nsj, ipc_fd)) {
			return;
		}
		uint32_t doneMsg;
		if (!util::recvMsg(ipc_fd, &doneMsg) || doneMsg != monitor::MSG_TAG_READY_H2J) {
			return;
		}
	}
	if (!contain::containProc(nsj)) {
		return;
	}

	if (!nsj->njc.keep_env()) {
		clearenv();
	}
	for (ssize_t i = 0; i < nsj->njc.envar_size(); i++) {
		putenv(const_cast<char*>(nsj->njc.envar(i).c_str()));
	}

	LOG_I("Executing %s for '%s'", QC(nsj->njc.exec_bin().path()), connstr.c_str());

	std::vector<const char*> argv;
	for (const auto& s : nsj->argv) {
		argv.push_back(s.c_str());
	}
	argv.push_back(nullptr);

	LOG_D("Exec: %s, Args: [%s]", QC(nsj->njc.exec_bin().path()), concatArgs(argv).c_str());

	/* Should be the last one in the sequence */
	if (!sandbox::applyPolicy(nsj, ipc_fd)) {
		return;
	}

	if (ipc_fd != -1) {
		if (!util::sendMsg(ipc_fd, monitor::MSG_TAG_READY_J2H)) {
			return;
		}
		uint32_t doneMsg;
		if (!util::recvMsg(ipc_fd, &doneMsg) || doneMsg != monitor::MSG_TAG_READY_H2J) {
			return;
		}
	}

	if (nsj->njc.exec_bin().exec_fd()) {
		util::syscall(__NR_execveat, nsj->exec_fd, (uintptr_t)"", (uintptr_t)argv.data(),
		    (uintptr_t)environ, AT_EMPTY_PATH);
	} else {
		execv(nsj->njc.exec_bin().path().c_str(), (char* const*)argv.data());
	}

	PLOG_E("execve(%s) failed", QC(nsj->njc.exec_bin().path()));
}

static void addProc(nsj_t* nsj, pid_t pid, int sock, int pidfd) {
	pids_t p;

	p.pid = pid;
	p.start = time(nullptr);

	p.remote_txt = net::connToText(sock, /* remote= */ true, &p.remote_addr);
	p.pasta_pid = -1;
	p.pidfd = pidfd;

	if (nsj->pids.find(pid) != nsj->pids.end()) {
		LOG_F("pid=%d already exists", pid);
	}

	LOG_D("Added pid=%d with start time %u to the queue for IP: '%s'", pid,
	    (unsigned int)p.start, p.remote_txt.c_str());

	nsj->pids.emplace(pid, std::move(p));
}

static void removeProc(nsj_t* nsj, pid_t pid) {
	if (nsj->pids.find(pid) == nsj->pids.end()) {
		LOG_W("pid=%d doesn't exist ?", pid);
		return;
	}

	auto& p = nsj->pids[pid];
	if (p.pasta_pid > 0) {
		LOG_D("Killing pasta pid=%d", p.pasta_pid);
		kill(p.pasta_pid, SIGKILL);
		TEMP_FAILURE_RETRY(waitpid(p.pasta_pid, nullptr, 0));
	}
	LOG_D("Removed pid=%d from the queue (IP:'%s', start time:'%s')", pid, p.remote_txt.c_str(),
	    util::timeToStr(p.start).c_str());

	if (p.thread.joinable()) {
		if (std::this_thread::get_id() == p.thread.get_id()) {
			p.thread.detach();
		} else {
			p.thread.join();
		}
	}

	/* pidfd is owned by pids_t - close it here on removal AFTER joining thread */
	if (p.pidfd >= 0) {
		close(p.pidfd);
	}

	nsj->pids.erase(pid);
}

int countProc(nsj_t* nsj) {
	return nsj->pids.size();
}

void displayProc(nsj_t* nsj) {
	LOG_I("Total number of spawned namespaces: %d", countProc(nsj));
	time_t now;
	now = time(nullptr);

	for (const auto& pid : nsj->pids) {
		time_t diff = now - pid.second.start;
		if (nsj->njc.time_limit() && (uint64_t)diff < nsj->njc.time_limit()) {
			uint64_t left = nsj->njc.time_limit() - (uint64_t)diff;
			LOG_I("pid=%d, Remote host: %s, Run time: %ld sec. (time left: %" PRIu64
			      " s.)",
			    pid.first, pid.second.remote_txt.c_str(), (long)diff, left);
		} else {
			LOG_I("pid=%d, Remote host: %s, Run time: %ld sec. (time left: %s)",
			    pid.first, pid.second.remote_txt.c_str(), (long)diff,
			    nsj->njc.time_limit() ? "expired" : "unlimited");
		}
	}
}

int reapProc(nsj_t* nsj, pid_t pid, bool should_wait) {
	siginfo_t si;
	memset(&si, 0, sizeof(si));
	if (TEMP_FAILURE_RETRY(waitid(P_PID, pid, &si, WEXITED | (should_wait ? 0 : WNOHANG))) ==
	    -1) {
		if (errno != ECHILD) {
			PLOG_W("waitid(P_PID, id=%d)", pid);
		}
		return 0;
	}

	if (si.si_pid == 0) {
		return 0;
	}

	if (nsj->njc.use_cgroupv2()) {
		cgroup2::finishFromParent(nsj, pid);
	} else {
		cgroup::finishFromParent(nsj, pid);
	}

	for (auto& pid_entry : nsj->pids) {
		if (pid_entry.second.pasta_pid > 0 && pid == pid_entry.second.pasta_pid) {
			int status = si.si_status;
			if (si.si_code == CLD_EXITED) {
				LOG_W("Pasta process %d exited unexpectedly with status %d. "
				      "Killing the jail.",
				    pid, status);
			} else {
				LOG_W("Pasta process %d terminated by signal %d. Killing the jail.",
				    pid, status);
				status = 128 + status;
			}
			util::syscall(
			    __NR_pidfd_send_signal, pid_entry.second.pidfd, SIGKILL, 0, 0);
			pid_entry.second.pasta_pid = -1;
			return status;
		}
	}

	std::string remote_txt = "[UNKNOWN]";
	const auto& p = nsj->pids.find(pid);
	if (p != nsj->pids.end()) {
		remote_txt = p->second.remote_txt;
	}

	if (si.si_code == CLD_EXITED) {
		nsj->exit_status = si.si_status;
		LOG_I("pid=%d (%s) exited with status: %d, (PIDs left: %d)", pid,
		    remote_txt.c_str(), si.si_status, countProc(nsj) - 1);
		removeProc(nsj, pid);
		return si.si_status;
	}
	if (si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED) {
		nsj->exit_status = 128 + si.si_status;
		LOG_I("pid=%d (%s) terminated with signal: %s (%d), (PIDs left: %d)", pid,
		    remote_txt.c_str(), util::sigName(si.si_status).c_str(), si.si_status,
		    countProc(nsj) - 1);
		removeProc(nsj, pid);
		return 128 + si.si_status;
	}

	LOG_W("pid=%d exited with unexpected si_code=%d, cleaning up", pid, si.si_code);
	nsj->exit_status = 1;
	removeProc(nsj, pid);
	return 0;
}

uint64_t checkTimeouts(
    nsj_t* nsj, pid_t target_pid, time_t start_time, const std::string& remote_txt, int pidfd) {
	if (nsj->njc.time_limit() == 0) {
		return -1; /* no timeout */
	}

	time_t now = time(nullptr);

	time_t diff = now - start_time;
	if ((uint64_t)diff >= nsj->njc.time_limit()) {
		LOG_I("pid=%d run time >= time limit (%ld >= %" PRIu64 ") (%s). Killing it",
		    target_pid, (long)diff, (uint64_t)nsj->njc.time_limit(), remote_txt.c_str());

		if (pidfd >= 0) {
			util::syscall(__NR_pidfd_send_signal, pidfd, SIGCONT, 0, 0);
			util::syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, 0, 0);
		} else {
			kill(target_pid, SIGCONT);
			kill(target_pid, SIGKILL);
		}
		return -1; /* Wait for pidfd to trigger */
	}
	uint64_t remaining = nsj->njc.time_limit() - diff;
	return remaining * 1000; /* in milliseconds */
}

int reapAll(nsj_t* nsj) {
	int rv = 0;
	siginfo_t si;

	for (;;) {
		si.si_pid = 0;
		if (TEMP_FAILURE_RETRY(waitid(P_ALL, 0, &si, WNOHANG | WNOWAIT | WEXITED)) == -1) {
			break;
		}
		if (si.si_pid == 0) {
			break;
		}

		rv = reapProc(nsj, si.si_pid);
	}
	return rv;
}

void killAll(nsj_t* nsj, int signal) {
	for (auto& pid_entry : nsj->pids) {
		pid_t pid = pid_entry.first;
		auto& p = pid_entry.second;

		if (p.pasta_pid > 0) {
			if (kill(p.pasta_pid, SIGKILL) == -1 && errno != ESRCH) {
				PLOG_W("kill(pasta_pid)");
			}
		}

		if (p.pidfd >= 0) {
			if (util::syscall(__NR_pidfd_send_signal, p.pidfd, signal, 0, 0) == -1 &&
			    errno != ESRCH) {
				PLOG_W("pidfd_send_signal(pidfd=%d, sig=%d)", p.pidfd, signal);
			}
		} else {
			kill(pid, signal);
		}
	}
}

static bool initParent(nsj_t* nsj, pid_t pid, int ipc_fd) {
	if (!net::initParent(nsj, pid, ipc_fd)) {
		LOG_W("Couldn't initialize net namespace for pid=%d", pid);
		return false;
	}

	if (nsj->njc.use_cgroupv2()) {
		if (!cgroup2::initNsFromParent(nsj, pid)) {
			LOG_E("Couldn't initialize cgroup 2 user namespace for pid=%d", pid);
			return false;
		}
	} else if (!cgroup::initNsFromParent(nsj, pid)) {
		LOG_E("Couldn't initialize cgroup user namespace for pid=%d", pid);
		return false;
	}

	if (!user::initNsFromParent(nsj, pid)) {
		LOG_W("Couldn't initialize user namespace for pid=%d", pid);
		return false;
	}

	if (ipc_fd != -1) {
		if (!util::sendMsg(ipc_fd, monitor::MSG_TAG_READY_H2J)) {
			LOG_W("Couldn't signal the new process via a socketpair");
			return false;
		}
	}

	/* unotify setup and second signaling are handled by the monitor thread */
	return true;
}

pid_t runChild(
    nsj_t* nsj, int netfd, int fd_in, int fd_out, int fd_err, int* pidfd_out, int* ipc_fd_out) {
	if (!net::limitConns(nsj, netfd)) {
		return 0;
	}
	uint64_t flags = 0UL;
	flags |= (nsj->njc.clone_newnet() ? CLONE_NEWNET : 0);
	flags |= (nsj->njc.clone_newuser() ? CLONE_NEWUSER : 0);
	flags |= (nsj->njc.clone_newns() ? CLONE_NEWNS : 0);
	flags |= (nsj->njc.clone_newpid() ? CLONE_NEWPID : 0);
	flags |= (nsj->njc.clone_newipc() ? CLONE_NEWIPC : 0);
	flags |= (nsj->njc.clone_newuts() ? CLONE_NEWUTS : 0);
	flags |= (nsj->njc.clone_newcgroup() ? CLONE_NEWCGROUP : 0);
	flags |= (nsj->njc.clone_newtime() ? CLONE_NEWTIME : 0);

	if (nsj->njc.mode() == nsjail::Mode::EXECVE) {
		LOG_D("unshare(flags: %s)", cloneFlagsToStr(flags).c_str());
		if (unshare(flags) == -1) {
			PLOG_F("unshare(%s)", cloneFlagsToStr(flags).c_str());
		}
		newProc(nsj, netfd, fd_in, fd_out, fd_err, -1);
		LOG_F("Launching new process failed");
	}

	LOG_D("Creating new process with clone flags:%s and exit_signal:SIGCHLD",
	    cloneFlagsToStr(flags).c_str());

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
		PLOG_W("socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) failed");
		return -1;
	}
	int child_fd = sv[0];
	int parent_fd = sv[1];

	pid_t pid = cloneProc(flags, SIGCHLD, pidfd_out);
	if (pid == 0) {
		close(parent_fd);

		newProc(nsj, netfd, fd_in, fd_out, fd_err, child_fd);
		util::sendMsg(child_fd, monitor::MSG_TAG_ERROR);
		LOG_E("Launching child process failed");
		pause();
		_exit(0xff);
	}
	close(child_fd);
	if (pid == -1) {
		auto saved_errno = errno;
		PLOG_W("clone(flags=%s) failed", cloneFlagsToStr(flags).c_str());
		close(parent_fd);
		errno = saved_errno;
		return pid;
	}
	addProc(nsj, pid, netfd, *pidfd_out);

	if (!initParent(nsj, pid, parent_fd)) {
		close(parent_fd);
		LOG_W("initParent failed, killing child pid=%d", pid);
		if (*pidfd_out >= 0) {
			util::syscall(__NR_pidfd_send_signal, *pidfd_out, SIGKILL, 0, 0);
		} else {
			kill(pid, SIGKILL);
		}
		reapProc(nsj, pid, true /* should_wait */);
		return -1;
	}

	*ipc_fd_out = parent_fd;
	return pid;
}

/*
 * Creates a new process via clone3(2) with CLONE_PIDFD.
 *
 * clone3() is mandatory - we require pidfd for process lifecycle management.
 *
 * Returns child pid in the parent, 0 in the child, -1 on error.
 * On success, *pidfd receives a file descriptor referring to the child.
 */
pid_t cloneProc(uint64_t flags, int exit_signal, int* pidfd) {
	exit_signal &= CSIGNAL;

	if (flags & CLONE_VM) {
		LOG_E("Cannot use clone(flags & CLONE_VM)");
		errno = 0;
		return -1;
	}

	if (flags & CLONE_NEWTIME) {
		LOG_W("CLONE_NEWTIME requested, but it's only supported with the unshare() mode "
		      "(-Me)");
	}

	struct clone_args ca = {};
	ca.exit_signal = (uint64_t)exit_signal;
	ca.flags = flags | CLONE_PIDFD | CLONE_CLEAR_SIGHAND;
	ca.pidfd = (uint64_t)pidfd;

	pid_t ret = util::syscall(__NR_clone3, (uintptr_t)&ca, sizeof(ca));
	if (ret == -1) {
		PLOG_W("clone3(flags=%s|CLONE_PIDFD) failed", cloneFlagsToStr(flags).c_str());
		return -1;
	}
	return ret;
}

/*
 * Lightweight clone3 wrapper for internal helpers (mnt, pid) that need
 * specific flags (e.g. CLONE_FS) but no pidfd tracking.
 */
pid_t cloneProcNoPidfd(uint64_t flags, int exit_signal) {
	exit_signal &= CSIGNAL;

	struct clone_args ca = {};
	ca.exit_signal = (uint64_t)exit_signal;
	ca.flags = flags;

	pid_t ret = util::syscall(__NR_clone3, (uintptr_t)&ca, sizeof(ca));
	if (ret == -1) {
		PLOG_W("clone3(flags=%s) failed", cloneFlagsToStr(flags).c_str());
	}
	return ret;
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

	pid_t pid = cloneProcNoPidfd(0, SIGCHLD);
	if (pid == -1) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (pid == 0) {
		close(sv[0]);
		execve(argv[0], (char* const*)argv.data(), (char* const*)env);
		PLOG_W("execve('%s')", argv[0]);
		util::writeToFd(sv[1], "A", 1);
		_exit(0);
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
		int ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, __WALL));
		if (ret == -1) {
			PLOG_W("waitpid(pid=%d)", pid);
			return -1;
		}
		if (WIFEXITED(status)) {
			int exit_code = WEXITSTATUS(status);
			LOG_D("pid=%d exited with exit code: %d", pid, exit_code);
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
			LOG_W("pid=%d killed by signal: %d (%s)", pid, exit_signal,
			    util::sigName(exit_signal).c_str());
			return 2;
		}
		LOG_W("Unknown exit status: %d", status);
	}
}

}  // namespace subproc
