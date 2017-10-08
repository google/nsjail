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
#include <sys/prctl.h>

#include "common.h"
#include "kafel.h"
#include "log.h"

#ifndef PR_SET_NO_NEW_PRIVS	/* in prctl.h since Linux 3.5 */
#define PR_SET_NO_NEW_PRIVS 38
#endif				/* PR_SET_NO_NEW_PRIVS */

static bool sandboxPrepareAndCommit(struct nsjconf_t *nsjconf)
{
	if (nsjconf->kafel_file == NULL && nsjconf->kafel_string == NULL) {
		return true;
	}
	struct sock_fprog seccomp_fprog;

	kafel_ctxt_t ctxt = kafel_ctxt_create();

	if (nsjconf->kafel_file != NULL) {
		kafel_set_input_file(ctxt, nsjconf->kafel_file);
	} else {
		kafel_set_input_string(ctxt, nsjconf->kafel_string);
	}

	if (kafel_compile(ctxt, &seccomp_fprog) != 0) {
		LOG_E("Could not compile policy: %s", kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		return false;
	}
	kafel_ctxt_destroy(&ctxt);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_fprog, 0, 0)) {
		PLOG_W("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
		return false;
	}
	return true;
}

bool sandboxApply(struct nsjconf_t * nsjconf)
{
	return sandboxPrepareAndCommit(nsjconf);
}
