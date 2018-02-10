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

#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "logs.h"
#include "subproc.h"

namespace pid {

bool initNs(nsjconf_t* nsjconf) {
	if (nsjconf->mode != MODE_STANDALONE_EXECVE) {
		return true;
	}
	if (!nsjconf->clone_newpid) {
		return true;
	}

	LOG_D("Creating a dummy 'init' process");

	/*
	 * If -Me is used then we need to create permanent init inside PID ns, otherwise only the
	 * first clone/fork will work, and the rest will fail with ENOMEM (see 'man pid_namespaces'
	 * for details on this behavior)
	 */
	pid_t pid = subproc::cloneProc(CLONE_FS);
	if (pid == -1) {
		PLOG_E("Couldn't create a dummy init process");
		return false;
	}
	if (pid > 0) {
		return true;
	}

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL) == -1) {
		PLOG_W("(prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
	}
	if (prctl(PR_SET_NAME, "ns-init", 0UL, 0UL, 0UL) == -1) {
		PLOG_W("(prctl(PR_SET_NAME, 'init') failed");
	}
	if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == -1) {
		PLOG_W("(prctl(PR_SET_DUMPABLE, 0) failed");
	}

	/* Act sort-a like a init by reaping zombie processes */
	struct sigaction sa;
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
	sa.sa_restorer = NULL;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		PLOG_W("Couldn't set sighandler for SIGCHLD");
	}

	for (;;) {
		pause();
	}
}

}  // namespace pid
