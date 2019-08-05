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

static bool containUserNs(nsjconf_t* nsjconf) {
	return user::initNsFromChild(nsjconf);
}

static bool containInitPidNs(nsjconf_t* nsjconf) {
	return pid::initNs(nsjconf);
}

static bool containInitNetNs(nsjconf_t* nsjconf) {
	return net::initNsFromChild(nsjconf);
}

static bool containInitUtsNs(nsjconf_t* nsjconf) {
	return uts::initNs(nsjconf);
}

static bool containInitCgroupNs(void) {
	return cgroup::initNs();
}

static bool containDropPrivs(nsjconf_t* nsjconf) {
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
	if (!nsjconf->disable_no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == -1) {
			/* Only new kernels support it */
			PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1)");
		}
	}

	if (!caps::initNs(nsjconf)) {
		return false;
	}

	return true;
}

static bool containPrepareEnv(nsjconf_t* nsjconf) {
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL)");
		return false;
	}
	if (nsjconf->personality && personality(nsjconf->personality) == -1) {
		PLOG_E("personality(%lx)", nsjconf->personality);
		return false;
	}
	LOG_D("setpriority(%d)", nsjconf->nice_level);
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, nsjconf->nice_level) == -1 && errno != 0) {
		PLOG_W("setpriority(%d)", nsjconf->nice_level);
	}
	if (!nsjconf->skip_setsid) {
		setsid();
	}
	return true;
}

static bool containInitMountNs(nsjconf_t* nsjconf) {
	return mnt::initNs(nsjconf);
}

static bool containCPU(nsjconf_t* nsjconf) {
	return cpu::initCpu(nsjconf);
}

static bool containSetLimits(nsjconf_t* nsjconf) {
	if (nsjconf->disable_rl) {
		return true;
	}

	struct rlimit64 rl;
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_as;
	if (setrlimit64(RLIMIT_AS, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_AS, %" PRIu64 ")", nsjconf->rl_as);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_core;
	if (setrlimit64(RLIMIT_CORE, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_CORE, %" PRIu64 ")", nsjconf->rl_core);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_cpu;
	if (setrlimit64(RLIMIT_CPU, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_CPU, %" PRIu64 ")", nsjconf->rl_cpu);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_fsize;
	if (setrlimit64(RLIMIT_FSIZE, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_FSIZE, %" PRIu64 ")", nsjconf->rl_fsize);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_nofile;
	if (setrlimit64(RLIMIT_NOFILE, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_NOFILE, %" PRIu64 ")", nsjconf->rl_nofile);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_nproc;
	if (setrlimit64(RLIMIT_NPROC, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_NPROC, %" PRIu64 ")", nsjconf->rl_nproc);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_stack;
	if (setrlimit64(RLIMIT_STACK, &rl) == -1) {
		PLOG_E("setrlimit64(0, RLIMIT_STACK, %" PRIu64 ")", nsjconf->rl_stack);
		return false;
	}
	return true;
}

static bool containPassFd(nsjconf_t* nsjconf, int fd) {
	return (std::find(nsjconf->openfds.begin(), nsjconf->openfds.end(), fd) !=
		nsjconf->openfds.end());
}

static bool containMakeFdsCOENaive(nsjconf_t* nsjconf) {
	/*
	 * Don't use getrlimit(RLIMIT_NOFILE) here, as it can return an artifically small value
	 * (e.g. 32), which could be smaller than a maximum assigned number to file-descriptors
	 * in this process. Just use some reasonably sane value (e.g. 1024)
	 */
	for (unsigned fd = 0; fd < 1024; fd++) {
		int flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
		if (flags == -1) {
			continue;
		}
		if (containPassFd(nsjconf, fd)) {
			LOG_D("fd=%d will be passed to the child process", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags & ~(FD_CLOEXEC))) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for fd=%d", fd);
				return false;
			}
		} else {
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for fd=%d", fd);
				return false;
			}
		}
	}
	return true;
}

static bool containMakeFdsCOEProc(nsjconf_t* nsjconf) {
	int dirfd = open("/proc/self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dirfd == -1) {
		PLOG_D("open('/proc/self/fd', O_DIRECTORY|O_RDONLY|O_CLOEXEC)");
		return false;
	}
	DIR* dir = fdopendir(dirfd);
	if (dir == NULL) {
		PLOG_W("fdopendir(fd=%d)", dirfd);
		close(dirfd);
		return false;
	}
	/* Make all fds above stderr close-on-exec */
	for (;;) {
		errno = 0;
		struct dirent* entry = readdir(dir);
		if (entry == NULL && errno != 0) {
			PLOG_D("readdir('/proc/self/fd')");
			closedir(dir);
			return false;
		}
		if (entry == NULL) {
			break;
		}
		if (strcmp(".", entry->d_name) == 0) {
			continue;
		}
		if (strcmp("..", entry->d_name) == 0) {
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
		if (containPassFd(nsjconf, fd)) {
			LOG_D("fd=%d will be passed to the child process", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags & ~(FD_CLOEXEC))) == -1) {
				PLOG_E("Could not clear FD_CLOEXEC for fd=%d", fd);
				closedir(dir);
				return false;
			}
		} else {
			LOG_D("fd=%d will be closed before execve()", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for fd=%d", fd);
				closedir(dir);
				return false;
			}
		}
	}
	closedir(dir);
	return true;
}

static bool containMakeFdsCOE(nsjconf_t* nsjconf) {
	if (containMakeFdsCOEProc(nsjconf)) {
		return true;
	}
	if (containMakeFdsCOENaive(nsjconf)) {
		return true;
	}
	LOG_E("Couldn't mark relevant file-descriptors as close-on-exec with any known method");
	return false;
}

bool setupFD(nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err) {
	if (nsjconf->stderr_to_null) {
		LOG_D("Redirecting fd=2 (STDERR_FILENO) to /dev/null");
		if ((fd_err = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR))) == -1) {
			PLOG_E("open('/dev/null', O_RDWR");
			return false;
		}
	}
	if (nsjconf->is_silent) {
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

bool containProc(nsjconf_t* nsjconf) {
	RETURN_ON_FAILURE(containUserNs(nsjconf));
	RETURN_ON_FAILURE(containInitPidNs(nsjconf));
	RETURN_ON_FAILURE(containInitMountNs(nsjconf));
	RETURN_ON_FAILURE(containInitNetNs(nsjconf));
	RETURN_ON_FAILURE(containInitUtsNs(nsjconf));
	RETURN_ON_FAILURE(containInitCgroupNs());
	RETURN_ON_FAILURE(containDropPrivs(nsjconf));
	;
	/* */
	/* As non-root */
	RETURN_ON_FAILURE(containCPU(nsjconf));
	RETURN_ON_FAILURE(containSetLimits(nsjconf));
	RETURN_ON_FAILURE(containPrepareEnv(nsjconf));
	RETURN_ON_FAILURE(containMakeFdsCOE(nsjconf));

	return true;
}

}  // namespace contain
