/*

   nsjail - isolating the binary
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

#include "contain.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#if __has_include(<linux/close_range.h>)
#include <linux/close_range.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>

#include "caps.h"
#include "cgroup.h"
#include "cgroup2.h"
#include "config.h"
#include "cpu.h"
#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "mnt.h"
#include "net.h"
#include "pid.h"
#include "user.h"
#include "util.h"
#include "uts.h"

namespace contain {

static bool containUserNs(nsj_t* nsj) {
	return user::initNs(nsj);
}

static bool containInitPidNs(nsj_t* nsj) {
	return pid::initNs(nsj);
}

static bool containInitNetNs(nsj_t* nsj) {
	return net::initNs(nsj);
}

static bool containInitUtsNs(nsj_t* nsj) {
	return uts::initNs(nsj);
}

static bool containInitCgroupNs(void) {
	return cgroup::initNs();
}

static bool containDropPrivs(nsj_t* nsj) {
	if (!nsj->njc.disable_no_new_privs()) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == -1) {
			/* Only new kernels support it */
			PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1)");
		}
	}

	if (!caps::initNs(nsj)) {
		return false;
	}

	return true;
}

static bool containPrepareEnv(nsj_t* nsj) {
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL)");
		return false;
	}
	unsigned long pers = 0;
	if (nsj->njc.persona_addr_compat_layout()) {
		pers |= ADDR_COMPAT_LAYOUT;
	}
	if (nsj->njc.persona_mmap_page_zero()) {
		pers |= MMAP_PAGE_ZERO;
	}
	if (nsj->njc.persona_read_implies_exec()) {
		pers |= READ_IMPLIES_EXEC;
	}
	if (nsj->njc.persona_addr_limit_3gb()) {
		pers |= ADDR_LIMIT_3GB;
	}
	if (nsj->njc.persona_addr_no_randomize()) {
		pers |= ADDR_NO_RANDOMIZE;
	}
	if (pers && personality(pers) == -1) {
		PLOG_E("personality(%lx)", pers);
		return false;
	}
	LOG_D("setpriority(%d)", nsj->njc.nice_level());
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, nsj->njc.nice_level()) == -1 && errno != 0) {
		PLOG_W("setpriority(%d)", nsj->njc.nice_level());
	}
	if (!nsj->njc.skip_setsid()) {
		setsid();
	}

	return true;
}

static bool containInitMountNs(nsj_t* nsj) {
	return mnt::initNs(nsj);
}

static bool containCPU(nsj_t* nsj) {
	return cpu::initCpu(nsj);
}

static bool containTSC(nsj_t* nsj) {
	if (nsj->njc.disable_tsc()) {
#if defined(__x86_64__) || defined(__i386__)
		if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) == -1) {
			PLOG_E("prctl(PR_SET_TSC, PR_TSC_SIGSEGV)");
			return false;
		}
#else  /* defined(__x86_64__) || defined(__i386__) */
		LOG_W("prctl(PR_SET_TSC, PR_TSC_SIGSEGV) requested, but it's supported under "
		      "x86/x86-64 CPU architectures only. Ignoring it!");
#endif /* defined(__x86_64__) || defined(__i386__) */
	}
	return true;
}

static bool containSetLimits(nsj_t* nsj) {
	if (nsj->njc.disable_rl()) {
		return true;
	}

	struct rlimit64 rl;
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_AS, nsj->njc.rlimit_as_type(), nsj->njc.rlimit_as(), 1024UL * 1024UL);
	if (util::setrlimit(RLIMIT_AS, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_AS, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_CORE, nsj->njc.rlimit_core_type(), nsj->njc.rlimit_core(), 1024UL * 1024UL);
	if (util::setrlimit(RLIMIT_CORE, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_CORE, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max =
	    config::adjustRLimit(RLIMIT_CPU, nsj->njc.rlimit_cpu_type(), nsj->njc.rlimit_cpu());
	if (util::setrlimit(RLIMIT_CPU, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_CPU, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_FSIZE, nsj->njc.rlimit_fsize_type(), nsj->njc.rlimit_fsize(), 1024UL * 1024UL);
	if (util::setrlimit(RLIMIT_FSIZE, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_FSIZE, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_NOFILE, nsj->njc.rlimit_nofile_type(), nsj->njc.rlimit_nofile());
	if (util::setrlimit(RLIMIT_NOFILE, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_NOFILE, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_NPROC, nsj->njc.rlimit_nproc_type(), nsj->njc.rlimit_nproc());
	if (util::setrlimit(RLIMIT_NPROC, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_NPROC, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_STACK, nsj->njc.rlimit_stack_type(), nsj->njc.rlimit_stack(), 1024UL * 1024UL);
	if (util::setrlimit(RLIMIT_STACK, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_STACK, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_MEMLOCK, nsj->njc.rlimit_memlock_type(), nsj->njc.rlimit_memlock(), 1024UL);
	if (util::setrlimit(RLIMIT_MEMLOCK, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_MEMLOCK, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_RTPRIO, nsj->njc.rlimit_rtprio_type(), nsj->njc.rlimit_rtprio());
	if (util::setrlimit(RLIMIT_RTPRIO, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_RTPRIO, %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = config::adjustRLimit(
	    RLIMIT_MSGQUEUE, nsj->njc.rlimit_msgqueue_type(), nsj->njc.rlimit_msgqueue());
	if (util::setrlimit(RLIMIT_MSGQUEUE, rl) == -1) {
		PLOG_E("util::setrlimit(0, RLIMIT_MSGQUEUE , %" PRIu64 ")", rl.rlim_cur);
		return false;
	}
	return true;
}

/*
 * Marks FDs for close-on-exec, or clears it for FDs that should be passed.
 * exec(2) handles the actual closing.
 */
static bool containMakeFdCOE(int fd, bool pass_fd) {
	int flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
	if (flags == -1) {
		if (errno == EBADF) {
			return true;
		}
		PLOG_W("fcntl(fd=%d, F_GETFD, 0)", fd);
		return false;
	}

	if (pass_fd) {
		LOG_D("fd=%d will be passed to the child process", fd);
		if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags & ~(FD_CLOEXEC))) == -1) {
			PLOG_E("Could not set FD_CLOEXEC for fd=%d", fd);
			return false;
		}
	} else {
		LOG_D("fd=%d will be closed before execve()", fd);
		if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1) {
			PLOG_E("Could not set FD_CLOEXEC for fd=%d", fd);
			return false;
		}
	}

	return true;
}

/*
 * Sets the Close-On-Exec (COE) flag on all file descriptors except those explicitly
 * marked to be passed to the sandbox.
 *
 * To optimize performance, we utilize the close_range() syscall. Because we are
 * single-threaded in the child process just before execve(), we can be _cheeky_ -
 * we blanket-apply CLOSE_RANGE_CLOEXEC to the entire descriptor table (0 to ~0U),
 * and then simply clear the flag on the exact FDs we wish to pass.
 */
static bool containMakeFdsCOE(nsj_t* nsj) {
	if (util::syscall(__NR_close_range, 0, ~0U, CLOSE_RANGE_CLOEXEC) == -1) {
		PLOG_E("close_range(0, ~0U, CLOSE_RANGE_CLOEXEC)");
		return false;
	}

	for (const auto fd : nsj->openfds) {
		if (fd >= 0) {
			containMakeFdCOE(fd, /* pass_fd= */ true);
		}
	}
	return true;
}

/*
 * (Violently) closes all file descriptors that are not explicitly required to survive
 * the containment boundary.
 *
 * Unlike COE above, closing an FD is a destructive and irreversible operation.
 * We cannot "close everything and revert". We must build a sorted list of critical
 * FDs (standard I/O, IPC sockets, logging, etc.) and safely jump over them by
 * calling close_range() on the numerical "gaps" between our preserved FDs.
 */
static bool containCloseFDs(nsj_t* nsj, int ipc_fd) {
	std::vector<unsigned int> keep_fds;

	/* Core standard I/O */
	keep_fds.push_back(STDIN_FILENO);
	keep_fds.push_back(STDOUT_FILENO);
	keep_fds.push_back(STDERR_FILENO);

	/* Crucial infrastructure */
	if (logs::logFd() > STDERR_FILENO) keep_fds.push_back(logs::logFd());
	if (ipc_fd >= 0) keep_fds.push_back(ipc_fd);
	if (nsj->njc.exec_bin().exec_fd() && nsj->exec_fd >= 0) {
		keep_fds.push_back(nsj->exec_fd);
	}

	/* User-requested passthrough FDs */
	for (const auto fd : nsj->openfds) {
		if (fd >= 0) keep_fds.push_back(fd);
	}

	/* Sort and deduplicate to safely iterate through the gaps */
	std::sort(keep_fds.begin(), keep_fds.end());
	keep_fds.erase(std::unique(keep_fds.begin(), keep_fds.end()), keep_fds.end());

	unsigned int range_start = 0;
	for (unsigned int target_fd : keep_fds) {
		/* If there is a gap between the start of our range and the target FD, close the gap
		 */
		if (target_fd > range_start) {
			if (util::syscall(__NR_close_range, range_start, target_fd - 1, 0) == -1) {
				PLOG_E("close_range(%u, %u, 0)", range_start, target_fd - 1);
				return false;
			}
		}

		/* Advance the start of the next range to be immediately after our target FD */
		range_start = target_fd + 1;
	}

	/* Finally, close all remaining file descriptors from the last target FD up to the system
	 * max */
	if (range_start < ~0U) {
		if (util::syscall(__NR_close_range, range_start, ~0U, 0) == -1) {
			PLOG_E("close_range(%u, ~0U, 0)", range_start);
			return false;
		}
	}
	return true;
}

bool setupFD(nsj_t* nsj, int fd_in, int fd_out, int fd_err, int ipc_fd) {
	if (nsj->njc.mode() == nsjail::Mode::LISTEN) {
		util::detachFromTTY();
	}
	if (nsj->njc.stderr_to_null()) {
		LOG_D("Redirecting fd=2 (STDERR_FILENO) to /dev/null");
		if ((fd_err = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR | O_CLOEXEC))) == -1) {
			PLOG_E("open('/dev/null', O_RDWR | O_CLOEXEC");
			return false;
		}
	}
	if (nsj->njc.silent()) {
		LOG_D("Redirecting fd=0-2 (STDIN/OUT/ERR_FILENO) to /dev/null");
		if (TEMP_FAILURE_RETRY(
			fd_in = fd_out = fd_err = open("/dev/null", O_RDWR | O_CLOEXEC)) == -1) {
			PLOG_E("open('/dev/null', O_RDWR | O_CLOEXEC)");
			return false;
		}
	}
	/* Set stdin/stdout/stderr to the net */
	if (fd_in != STDIN_FILENO && TEMP_FAILURE_RETRY(dup2(fd_in, STDIN_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDIN_FILENO)", fd_in);
		return false;
	}
	if (fd_out != STDOUT_FILENO && TEMP_FAILURE_RETRY(dup2(fd_out, STDOUT_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDOUT_FILENO)", fd_out);
		return false;
	}
	if (fd_err != STDERR_FILENO && TEMP_FAILURE_RETRY(dup2(fd_err, STDERR_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDERR_FILENO)", fd_err);
		return false;
	}
	if (!contain::containCloseFDs(nsj, ipc_fd)) {
		return false;
	}
	return true;
}

bool containProc(nsj_t* nsj) {
	RETURN_ON_FAILURE(containUserNs(nsj));
	RETURN_ON_FAILURE(containInitPidNs(nsj));
	RETURN_ON_FAILURE(containInitMountNs(nsj));
	RETURN_ON_FAILURE(containInitNetNs(nsj));
	RETURN_ON_FAILURE(containInitUtsNs(nsj));
	RETURN_ON_FAILURE(containInitCgroupNs());
	RETURN_ON_FAILURE(containDropPrivs(nsj));

	/* As non-root */
	RETURN_ON_FAILURE(containCPU(nsj));
	RETURN_ON_FAILURE(containTSC(nsj));
	RETURN_ON_FAILURE(containSetLimits(nsj));
	RETURN_ON_FAILURE(containPrepareEnv(nsj));
	RETURN_ON_FAILURE(containMakeFdsCOE(nsj));

	return true;
}

}  // namespace contain
