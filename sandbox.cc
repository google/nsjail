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
#include "log.h"
}

namespace sandbox {

#ifndef PR_SET_NO_NEW_PRIVS /* in prctl.h since Linux 3.5 */
#define PR_SET_NO_NEW_PRIVS 38
#endif /* PR_SET_NO_NEW_PRIVS */

static bool prepareAndCommit(struct nsjconf_t* nsjconf) {
	if (nsjconf->kafel_file_path == NULL && nsjconf->kafel_string == NULL) {
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

bool applyPolicy(struct nsjconf_t* nsjconf) { return prepareAndCommit(nsjconf); }

bool preparePolicy(struct nsjconf_t* nsjconf) {
	if (nsjconf->kafel_file_path == NULL && nsjconf->kafel_string == NULL) {
		return true;
	}
	FILE* f = NULL;
	if (nsjconf->kafel_file_path && !(f = fopen(nsjconf->kafel_file_path, "r"))) {
		PLOG_W(
		    "Couldn't open the kafel seccomp policy file '%s'", nsjconf->kafel_file_path);
		return false;
	}

	kafel_ctxt_t ctxt = kafel_ctxt_create();

	if (f) {
		kafel_set_input_file(ctxt, f);
	} else if (nsjconf->kafel_string) {
		kafel_set_input_string(ctxt, nsjconf->kafel_string);
	} else {
		LOG_F(
		    "No kafel seccomp-bpf config file available, nor policy as a string was "
		    "defined");
	}

	if (kafel_compile(ctxt, &nsjconf->seccomp_fprog) != 0) {
		LOG_E("Could not compile policy: %s", kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		return false;
	}
	kafel_ctxt_destroy(&ctxt);
	return true;
}

}  // namespace sandbox
