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
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <unistd.h>

extern "C" {
#include "log.h"
#include "mount.h"
}

#include "caps.h"
#include "cgroup.h"
#include "cpu.h"
#include "net.h"
#include "pid.h"
#include "user.h"
#include "uts.h"

namespace contain {

static bool containUserNs(struct nsjconf_t* nsjconf) { return user::initNsFromChild(nsjconf); }

static bool containInitPidNs(struct nsjconf_t* nsjconf) { return pid::initNs(nsjconf); }

static bool containInitNetNs(struct nsjconf_t* nsjconf) { return net::initNsFromChild(nsjconf); }

static bool containInitUtsNs(struct nsjconf_t* nsjconf) { return uts::initNs(nsjconf); }

static bool containInitCgroupNs(void) { return cgroup::initNs(); }

static bool containDropPrivs(struct nsjconf_t* nsjconf) {
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
	if (nsjconf->disable_no_new_privs == false) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == -1) {
			/* Only new kernels support it */
			PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1)");
		}
	}

	if (caps::initNs(nsjconf) == false) {
		return false;
	}

	return true;
}

static bool containPrepareEnv(struct nsjconf_t* nsjconf) {
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL)");
		return false;
	}
	if (nsjconf->personality && personality(nsjconf->personality) == -1) {
		PLOG_E("personality(%lx)", nsjconf->personality);
		return false;
	}
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, 19) == -1 && errno != 0) {
		PLOG_W("setpriority(19)");
	}
	if (nsjconf->skip_setsid == false) {
		setsid();
	}
	return true;
}

static bool containInitMountNs(struct nsjconf_t* nsjconf) { return mountInitNs(nsjconf); }

static bool containCPU(struct nsjconf_t* nsjconf) { return cpu::initCpu(nsjconf); }

static bool containSetLimits(struct nsjconf_t* nsjconf) {
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

static bool containPassFd(struct nsjconf_t* nsjconf, int fd) {
	struct ints_t* p;
	TAILQ_FOREACH(p, &nsjconf->open_fds, pointers) {
		if (p->val == fd) {
			return true;
		}
	}
	return false;
}

static bool containMakeFdsCOENaive(struct nsjconf_t* nsjconf) {
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
			LOG_D("FD=%d will be passed to the child process", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags & ~(FD_CLOEXEC))) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for FD=%d", fd);
				return false;
			}
		} else {
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for FD=%d", fd);
				return false;
			}
		}
	}
	return true;
}

static bool containMakeFdsCOEProc(struct nsjconf_t* nsjconf) {
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
		int fd = strtoul(entry->d_name, NULL, 10);
		if (errno == EINVAL) {
			LOG_W("Cannot convert /proc/self/fd/%s to a number", entry->d_name);
			continue;
		}
		int flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD, 0));
		if (flags == -1) {
			PLOG_D("fcntl(fd, F_GETFD, 0)");
			closedir(dir);
			return false;
		}
		if (containPassFd(nsjconf, fd)) {
			LOG_D("FD=%d will be passed to the child process", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags & ~(FD_CLOEXEC))) == -1) {
				PLOG_E("Could not clear FD_CLOEXEC for FD=%d", fd);
				closedir(dir);
				return false;
			}
		} else {
			LOG_D("FD=%d will be closed before execve()", fd);
			if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1) {
				PLOG_E("Could not set FD_CLOEXEC for FD=%d", fd);
				closedir(dir);
				return false;
			}
		}
	}
	closedir(dir);
	return true;
}

static bool containMakeFdsCOE(struct nsjconf_t* nsjconf) {
	if (containMakeFdsCOEProc(nsjconf)) {
		return true;
	}
	if (containMakeFdsCOENaive(nsjconf)) {
		return true;
	}
	LOG_E("Couldn't mark relevant file-descriptors as close-on-exec with any known method");
	return false;
}

bool setupFD(struct nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err) {
	if (nsjconf->mode != MODE_LISTEN_TCP) {
		if (nsjconf->is_silent == false) {
			return true;
		}
		if (TEMP_FAILURE_RETRY(fd_in = fd_out = fd_err = open("/dev/null", O_RDWR)) == -1) {
			PLOG_E("open('/dev/null', O_RDWR)");
			return false;
		}
	}
	/* Set stdin/stdout/stderr to the net */
	if (TEMP_FAILURE_RETRY(dup2(fd_in, STDIN_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDIN_FILENO)", fd_in);
		return false;
	}
	if (TEMP_FAILURE_RETRY(dup2(fd_out, STDOUT_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDOUT_FILENO)", fd_out);
		return false;
	}
	if (TEMP_FAILURE_RETRY(dup2(fd_err, STDERR_FILENO)) == -1) {
		PLOG_E("dup2(%d, STDERR_FILENO)", fd_err);
		return false;
	}
	return true;
}

bool containProc(struct nsjconf_t* nsjconf) {
	if (containUserNs(nsjconf) == false) {
		return false;
	}
	if (containInitPidNs(nsjconf) == false) {
		return false;
	}
	if (containInitMountNs(nsjconf) == false) {
		return false;
	}
	if (containInitNetNs(nsjconf) == false) {
		return false;
	}
	if (containInitUtsNs(nsjconf) == false) {
		return false;
	}
	if (containInitCgroupNs() == false) {
		return false;
	}
	if (containDropPrivs(nsjconf) == false) {
		return false;
	}
	/* */
	/* As non-root */
	if (containCPU(nsjconf) == false) {
		return false;
	}
	if (containSetLimits(nsjconf) == false) {
		return false;
	}
	if (containPrepareEnv(nsjconf) == false) {
		return false;
	}
	if (containMakeFdsCOE(nsjconf) == false) {
		return false;
	}
	return true;
}

}  // namespace contain
