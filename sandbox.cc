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
#include <sys/prctl.h>

extern "C" {
#include "kafel.h"
}
#include "logs.h"

namespace sandbox {

#ifndef PR_SET_NO_NEW_PRIVS /* in prctl.h since Linux 3.5 */
#define PR_SET_NO_NEW_PRIVS 38
#endif /* PR_SET_NO_NEW_PRIVS */

static bool prepareAndCommit(nsjconf_t* nsjconf) {
	if (nsjconf->kafel_file_path.empty() && nsjconf->kafel_string.empty()) {
		return true;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &nsjconf->seccomp_fprog, 0, 0)) {
		PLOG_W("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
		return false;
	}
	return true;
}

bool applyPolicy(nsjconf_t* nsjconf) {
	return prepareAndCommit(nsjconf);
}

bool preparePolicy(nsjconf_t* nsjconf) {
	if (nsjconf->kafel_file_path.empty() && nsjconf->kafel_string.empty()) {
		return true;
	}
	if (!nsjconf->kafel_file_path.empty() && !nsjconf->kafel_string.empty()) {
		LOG_W(
		    "You specified both kafel seccomp policy, and kafel seccomp file. Specify one "
		    "only");
		return false;
	}

	kafel_ctxt_t ctxt = kafel_ctxt_create();

	if (!nsjconf->kafel_file_path.empty()) {
		FILE* f = fopen(nsjconf->kafel_file_path.c_str(), "r");
		if (!f) {
			PLOG_W("Couldn't open the kafel seccomp policy file '%s'",
			    nsjconf->kafel_file_path.c_str());
			kafel_ctxt_destroy(&ctxt);
			return false;
		}
		LOG_D("Compiling seccomp policy from file: '%s'", nsjconf->kafel_file_path.c_str());
		kafel_set_input_file(ctxt, f);
	}
	if (!nsjconf->kafel_string.empty()) {
		LOG_D("Compiling seccomp policy from string: '%s'", nsjconf->kafel_string.c_str());
		kafel_set_input_string(ctxt, nsjconf->kafel_string.c_str());
	}

	if (kafel_compile(ctxt, &nsjconf->seccomp_fprog) != 0) {
		LOG_W("Could not compile policy: %s", kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		return false;
	}
	kafel_ctxt_destroy(&ctxt);
	return true;
}

}  // namespace sandbox
