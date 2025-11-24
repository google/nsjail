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

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" {
#include "kafel.h"
}
#include "logs.h"
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

static bool prepareAndCommit(nsj_t* nsj) {
	if (nsj->njc.seccomp_policy_file().empty() && nsj->njc.seccomp_string().empty()) {
		return true;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}
	if (nsj->njc.seccomp_log()) {
#ifndef __NR_seccomp
		LOG_E("The __NR_seccomp is not defined with this kernel's header files (kernel "
		      "headers too old?)");
		return false;
#else
		if (util::syscall(__NR_seccomp, (uintptr_t)SECCOMP_SET_MODE_FILTER,
			(uintptr_t)(SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG),
			(uintptr_t)&nsj->seccomp_fprog) == -1) {
			PLOG_E("seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC | "
			       "SECCOMP_FILTER_FLAG_LOG) failed");
			return false;
		}
		return true;
#endif /* __NR_seccomp */
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &nsj->seccomp_fprog, 0UL, 0UL)) {
		PLOG_W("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
		return false;
	}
	return true;
}

bool applyPolicy(nsj_t* nsj) {
	return prepareAndCommit(nsj);
}

bool preparePolicy(nsj_t* nsj) {
	if (nsj->njc.seccomp_policy_file().empty() && nsj->njc.seccomp_string().empty()) {
		return true;
	}
	if (!nsj->njc.seccomp_policy_file().empty() && !nsj->njc.seccomp_string().empty()) {
		LOG_W("You specified both kafel seccomp policy, and kafel seccomp file. Specify "
		      "one only");
		return false;
	}

	kafel_ctxt_t ctxt = kafel_ctxt_create();

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
	}
	for (const auto& s : nsj->njc.seccomp_string()) {
		LOG_D("Compiling seccomp policy from string: '%s'", s.c_str());
		kafel_set_input_string(ctxt, s.c_str());
	}

	if (kafel_compile(ctxt, &nsj->seccomp_fprog) != 0) {
		LOG_W("Could not compile policy: %s", kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		return false;
	}
	kafel_ctxt_destroy(&ctxt);
	return true;
}

void closePolicy(nsj_t* nsj) {
	if (!nsj->seccomp_fprog.filter) {
		return;
	}
	free(nsj->seccomp_fprog.filter);
	nsj->seccomp_fprog.filter = nullptr;
	nsj->seccomp_fprog.len = 0;
}

}  // namespace sandbox
