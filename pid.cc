/*

   nsjail - CLONE_PID routines
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

#include "pid.h"

#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logs.h"
#include "subproc.h"
#include "util.h"

namespace pid {

bool initNs(nsj_t* nsj) {
	if (nsj->njc.mode() != nsjail::Mode::EXECVE) {
		return true;
	}
	if (!nsj->njc.clone_newpid()) {
		return true;
	}

	LOG_D("Creating a dummy 'init' process");
	int status_pipe[2];
	if (pipe2(status_pipe, O_CLOEXEC) == -1) {
		PLOG_E("Couldn't create status pipe for dummy init process");
		return false;
	}

	/*
	 * If -Me is used then we need to create permanent init inside PID ns, otherwise only the
	 * first clone/fork will work, and the rest will fail with ENOMEM (see 'man pid_namespaces'
	 * for details on this behavior)
	 */
	pid_t pid = subproc::cloneProc(CLONE_FS, 0);
	if (pid == -1) {
		close(status_pipe[0]);
		close(status_pipe[1]);
		PLOG_E("Couldn't create a dummy init process");
		return false;
	}
	if (pid > 0) {
		close(status_pipe[1]);
		char status;
		const bool initialized =
		    util::readFromFd(status_pipe[0], &status, sizeof(status)) == sizeof(status) &&
		    status == 'I';
		close(status_pipe[0]);
		if (!initialized) {
			LOG_E("Dummy init process failed to initialize");
			kill(pid, SIGKILL);
			while (waitpid(pid, nullptr, __WALL) == -1 && errno == EINTR) {
			}
			return false;
		}
		LOG_D("Created a dummy 'init' process with PID=%d", pid);
		return true;
	}
	close(status_pipe[0]);

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
		_exit(EXIT_FAILURE);
	}
	if (prctl(PR_SET_NAME, "ns-init", 0UL, 0UL, 0UL) == -1) {
		PLOG_W("prctl(PR_SET_NAME, 'init') failed");
	}
	if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == -1) {
		PLOG_E("prctl(PR_SET_DUMPABLE, 0) failed");
		_exit(EXIT_FAILURE);
	}

	/* Act sort-a like a init by reaping zombie processes */
	struct sigaction sa = {};
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
	sa.sa_restorer = NULL;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		PLOG_E("Couldn't set sighandler for SIGCHLD");
		_exit(EXIT_FAILURE);
	}

	const char initialized = 'I';
	if (!util::writeToFd(status_pipe[1], &initialized, sizeof(initialized))) {
		_exit(EXIT_FAILURE);
	}
	close(status_pipe[1]);

	for (;;) {
		pause();
	}
}

}  // namespace pid
