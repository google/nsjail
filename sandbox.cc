/*

   nsjail - seccomp-bpf sandboxing
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

#include "sandbox.h"

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "subproc.h"

extern "C" {
#include "kafel.h"
}
#include "logs.h"
#include "unotify/syscall_defs.h"
#include "util.h"

namespace sandbox {

#ifndef PR_SET_NO_NEW_PRIVS /* in prctl.h since Linux 3.5 */
#define PR_SET_NO_NEW_PRIVS 38
#endif /* PR_SET_NO_NEW_PRIVS */

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif /* SECCOMP_FILTER_FLAG_TSYNC */

#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif /* SECCOMP_FILTER_FLAG_LOG */

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif /* SECCOMP_FILTER_FLAG_NEW_LISTENER */

bool installUnotifyFilter(nsj_t* nsj, int pipefd) {
	if (!nsj->njc.seccomp_unotify()) {
		return true;
	}
	if (nsj->seccomp_unotify_fprog.len == 0) {
		LOG_E("seccomp_unotify enabled but no BPF program compiled");
		return false;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}

	int ret = util::syscall(__NR_seccomp, (uintptr_t)SECCOMP_SET_MODE_FILTER,
	    (uintptr_t)SECCOMP_FILTER_FLAG_NEW_LISTENER, (uintptr_t)&nsj->seccomp_unotify_fprog);
	if (ret == -1) {
		PLOG_E("seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER) failed");
		return false;
	}
	int unotif_fd = ret;

	if (fcntl(unotif_fd, F_SETFD, FD_CLOEXEC) == -1) {
		PLOG_E("fcntl(unotif_fd, F_SETFD, FD_CLOEXEC) failed");
		close(unotif_fd);
		return false;
	}

	if (!util::sendFd(pipefd, unotif_fd)) {
		PLOG_E("sendFd(unotif_fd) to parent failed");
		close(unotif_fd);
		return false;
	}
	LOG_D("Child: sent unotif_fd=%d to parent", unotif_fd);
	close(unotif_fd);
	return true;
}

static bool prepareAndCommit(nsj_t* nsj) {
	if (nsj->seccomp_fprog.len == 0) {
		return true;
	}

	/* PR_SET_NO_NEW_PRIVS is idempotent; may already be set by installUnotifyFilter */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}

	unsigned int flags = 0;
	if (nsj->njc.seccomp_log()) {
		flags |= (SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_TSYNC);
	}

	if (flags != 0) {
		int ret = util::syscall(__NR_seccomp, (uintptr_t)SECCOMP_SET_MODE_FILTER,
		    (uintptr_t)flags, (uintptr_t)&nsj->seccomp_fprog);
		if (ret == -1) {
			PLOG_E("seccomp(SECCOMP_SET_MODE_FILTER) failed");
			return false;
		}
	} else {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &nsj->seccomp_fprog, 0, 0)) {
			PLOG_W("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
			return false;
		}
	}
	return true;
}

bool applyPolicy(nsj_t* nsj, int pipefd) {
	if (pipefd != -1 && nsj->njc.seccomp_unotify()) {
		if (!installUnotifyFilter(nsj, pipefd)) {
			return false;
		}
	}
	return prepareAndCommit(nsj);
}

bool preparePolicy(nsj_t* nsj) {
	nsj->seccomp_fprog.len = 0;
	nsj->seccomp_fprog.filter = NULL;
	nsj->seccomp_unotify_fprog.len = 0;
	nsj->seccomp_unotify_fprog.filter = NULL;

	if (nsj->njc.seccomp_policy_file().empty() && nsj->njc.seccomp_string().empty() &&
	    !nsj->njc.seccomp_unotify()) {
		return true;
	}
	if (!nsj->njc.seccomp_policy_file().empty() && !nsj->njc.seccomp_string().empty()) {
		LOG_W("You specified both kafel seccomp policy, and kafel seccomp file. Specify "
		      "one only");
		return false;
	}

	if (nsj->njc.seccomp_unotify()) {
		kafel_ctxt_t unotify_ctxt = kafel_ctxt_create();
		std::string unotify_policy = unotify::buildKafelPolicy();
		kafel_set_input_string(unotify_ctxt, unotify_policy.c_str());
		if (kafel_compile(unotify_ctxt, &nsj->seccomp_unotify_fprog) != 0) {
			LOG_E("Could not compile the default unotify seccomp policy: %s",
			    kafel_error_msg(unotify_ctxt));
			kafel_ctxt_destroy(&unotify_ctxt);
			return false;
		}
		kafel_ctxt_destroy(&unotify_ctxt);
	}

	if (nsj->njc.seccomp_policy_file().empty() && nsj->njc.seccomp_string().empty()) {
		return true;
	}

	kafel_ctxt_t ctxt = kafel_ctxt_create();
	std::string combined_seccomp_policy;
	if (!nsj->njc.seccomp_policy_file().empty()) {
		FILE* f = fopen(nsj->njc.seccomp_policy_file().c_str(), "r");
		if (!f) {
			PLOG_W("Couldn't open the kafel seccomp policy file '%s'",
			    nsj->njc.seccomp_policy_file().c_str());
			kafel_ctxt_destroy(&ctxt);
			return false;
		}
		LOG_D("Compiling seccomp policy from file: '%s'",
		    nsj->njc.seccomp_policy_file().c_str());
		kafel_set_input_file(ctxt, f);
	} else {
		for (const auto& s : nsj->njc.seccomp_string()) {
			combined_seccomp_policy += s;
			combined_seccomp_policy += '\n';
		}
		if (!combined_seccomp_policy.empty()) {
			LOG_D("Compiling seccomp policy from string:\n%s",
			    combined_seccomp_policy.c_str());
			kafel_set_input_string(ctxt, combined_seccomp_policy.c_str());
		}
	}

	if (kafel_compile(ctxt, &nsj->seccomp_fprog) != 0) {
		LOG_E("Could not compile policy: %s", kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		return false;
	}
	kafel_ctxt_destroy(&ctxt);

	return true;
}

void closePolicy(nsj_t* nsj) {
	if (nsj->seccomp_fprog.filter) {
		free(nsj->seccomp_fprog.filter);
		nsj->seccomp_fprog.filter = nullptr;
		nsj->seccomp_fprog.len = 0;
	}
	if (nsj->seccomp_unotify_fprog.filter) {
		free(nsj->seccomp_unotify_fprog.filter);
		nsj->seccomp_unotify_fprog.filter = nullptr;
		nsj->seccomp_unotify_fprog.len = 0;
	}
}

}  // namespace sandbox
