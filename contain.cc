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
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
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
	unsigned long personality = 0;
	if (nsj->njc.persona_addr_compat_layout()) {
		personality |= ADDR_COMPAT_LAYOUT;
	}
	if (nsj->njc.persona_mmap_page_zero()) {
		personality |= MMAP_PAGE_ZERO;
	}
	if (nsj->njc.persona_read_implies_exec()) {
		personality |= READ_IMPLIES_EXEC;
	}
	if (nsj->njc.persona_addr_limit_3gb()) {
		personality |= ADDR_LIMIT_3GB;
	}
	if (nsj->njc.persona_addr_no_randomize()) {
		personality |= ADDR_NO_RANDOMIZE;
	}
	if (personality && ::personality(personality) == -1) {
		PLOG_E("personality(%lx)", personality);
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

static bool containPassFd(nsj_t* nsj, int fd) {
	return (std::find(nsj->openfds.begin(), nsj->openfds.end(), fd) != nsj->openfds.end());
}

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

static bool containMakeFdsCOECloseRange(nsj_t* nsj) {
	RETURN_ON_FAILURE(util::makeRangeCOE(0U, ~0U));
	for (const auto fd : nsj->openfds) {
		RETURN_ON_FAILURE(containMakeFdCOE(fd, /* pass_fd= */ true));
	}
	return true;
}

static bool containMakeFdsCOENaive(nsj_t* nsj) {
	/*
	 * Don't use getrlimit(RLIMIT_NOFILE) here, as it can return an artifically small value
	 * (e.g. 32), which could be smaller than a maximum assigned number to file-descriptors
	 * in this process. Just use some reasonably sane value (e.g. 1024)
	 */
	for (unsigned fd = 0; fd < 1024; fd++) {
		RETURN_ON_FAILURE(containMakeFdCOE(fd, containPassFd(nsj, fd)));
	}
	return true;
}

static bool containMakeFdsCOEProc(nsj_t* nsj) {
	int dirfd = open("/proc/self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dirfd == -1) {
		PLOG_D("open('/proc/self/fd', O_DIRECTORY|O_RDONLY|O_CLOEXEC)");
		return false;
	}
	DIR* dir = fdopendir(dirfd);
	if (dir == nullptr) {
		PLOG_W("fdopendir(fd=%d)", dirfd);
		close(dirfd);
		return false;
	}
	/* Make all fds above stderr close-on-exec */
	for (;;) {
		errno = 0;
		struct dirent* entry = readdir(dir);
		if (entry == nullptr && errno != 0) {
			PLOG_D("readdir('/proc/self/fd')");
			closedir(dir);
			return false;
		}
		if (entry == nullptr) {
			break;
		}
		if (util::StrEq(".", entry->d_name)) {
			continue;
		}
		if (util::StrEq("..", entry->d_name)) {
			continue;
		}
		errno = 0;
		int fd = strtoimax(entry->d_name, NULL, 10);
		if (errno != 0) {
			PLOG_W("Cannot convert /proc/self/fd/%s to a number", entry->d_name);
			continue;
		}
		int flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
		if (flags == -1) {
			PLOG_D("fcntl(fd=%d, F_GETFD, 0)", fd);
			closedir(dir);
			return false;
		}
		RETURN_ON_FAILURE(containMakeFdCOE(fd, containPassFd(nsj, fd)));
	}
	closedir(dir);
	return true;
}

static bool containMakeFdsCOE(nsj_t* nsj) {
	if (containMakeFdsCOECloseRange(nsj)) {
		return true;
	}
	if (containMakeFdsCOEProc(nsj)) {
		return true;
	}
	if (containMakeFdsCOENaive(nsj)) {
		return true;
	}
	LOG_E("Couldn't mark relevant file-descriptors as close-on-exec with any known method");
	return false;
}

bool setupFD(nsj_t* nsj, int fd_in, int fd_out, int fd_err) {
	if (nsj->njc.stderr_to_null()) {
		LOG_D("Redirecting fd=2 (STDERR_FILENO) to /dev/null");
		if ((fd_err = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR))) == -1) {
			PLOG_E("open('/dev/null', O_RDWR");
			return false;
		}
	}
	if (nsj->njc.silent()) {
		LOG_D("Redirecting fd=0-2 (STDIN/OUT/ERR_FILENO) to /dev/null");
		if (TEMP_FAILURE_RETRY(fd_in = fd_out = fd_err = open("/dev/null", O_RDWR)) == -1) {
			PLOG_E("open('/dev/null', O_RDWR)");
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
	;
	/* */
	/* As non-root */
	RETURN_ON_FAILURE(containCPU(nsj));
	RETURN_ON_FAILURE(containTSC(nsj));
	RETURN_ON_FAILURE(containSetLimits(nsj));
	RETURN_ON_FAILURE(containPrepareEnv(nsj));
	RETURN_ON_FAILURE(containMakeFdsCOE(nsj));

	return true;
}

}  // namespace contain
