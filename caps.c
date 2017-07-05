/*

   nsjail - capability-related operations
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

#include "caps.h"

#include <sys/capability.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

#define VALSTR_STRUCT(x) { x, #x }

/*  *INDENT-OFF* */
static struct {
	const int val;
    const char* const name;
} const capNames[] = {
    VALSTR_STRUCT(CAP_CHOWN),
    VALSTR_STRUCT(CAP_DAC_OVERRIDE),
    VALSTR_STRUCT(CAP_DAC_READ_SEARCH),
    VALSTR_STRUCT(CAP_FOWNER),
    VALSTR_STRUCT(CAP_FSETID),
    VALSTR_STRUCT(CAP_KILL),
    VALSTR_STRUCT(CAP_SETGID),
    VALSTR_STRUCT(CAP_SETUID),
    VALSTR_STRUCT(CAP_SETPCAP),
    VALSTR_STRUCT(CAP_LINUX_IMMUTABLE),
    VALSTR_STRUCT(CAP_NET_BIND_SERVICE),
    VALSTR_STRUCT(CAP_NET_BROADCAST),
    VALSTR_STRUCT(CAP_NET_ADMIN),
    VALSTR_STRUCT(CAP_NET_RAW),
    VALSTR_STRUCT(CAP_IPC_LOCK),
    VALSTR_STRUCT(CAP_IPC_OWNER),
    VALSTR_STRUCT(CAP_SYS_MODULE),
    VALSTR_STRUCT(CAP_SYS_RAWIO),
    VALSTR_STRUCT(CAP_SYS_CHROOT),
    VALSTR_STRUCT(CAP_SYS_PTRACE),
    VALSTR_STRUCT(CAP_SYS_PACCT),
    VALSTR_STRUCT(CAP_SYS_ADMIN),
    VALSTR_STRUCT(CAP_SYS_BOOT),
    VALSTR_STRUCT(CAP_SYS_NICE),
    VALSTR_STRUCT(CAP_SYS_RESOURCE),
    VALSTR_STRUCT(CAP_SYS_TIME),
    VALSTR_STRUCT(CAP_SYS_TTY_CONFIG),
    VALSTR_STRUCT(CAP_MKNOD),
    VALSTR_STRUCT(CAP_LEASE),
    VALSTR_STRUCT(CAP_AUDIT_WRITE),
    VALSTR_STRUCT(CAP_AUDIT_CONTROL),
    VALSTR_STRUCT(CAP_SETFCAP),
    VALSTR_STRUCT(CAP_MAC_OVERRIDE),
    VALSTR_STRUCT(CAP_MAC_ADMIN),
    VALSTR_STRUCT(CAP_SYSLOG),
    VALSTR_STRUCT(CAP_WAKE_ALARM),
    VALSTR_STRUCT(CAP_BLOCK_SUSPEND),
    VALSTR_STRUCT(CAP_AUDIT_READ),
};
/*  *INDENT-ON* */

int capsNameToVal(const char *name)
{
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (strcmp(name, capNames[i].name) == 0) {
			return capNames[i].val;
		}
	}
	LOG_W("Uknown capability: '%s'", name);
	return -1;
}

static const char *capsValToStr(int val)
{
	static __thread char capsStr[1024];
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (val == capNames[i].val) {
			snprintf(capsStr, sizeof(capsStr), "%s", capNames[i].name);
			return capsStr;
		}
	}

	snprintf(capsStr, sizeof(capsStr), "CAP_UNKNOWN(%d)", val);
	return capsStr;
}

bool capsInitInternal(struct nsjconf_t * nsjconf, bool is_global)
{
	cap_t cap_orig = cap_get_pid(getpid());
	if (cap_orig == NULL) {
		PLOG_W("capget(PID=%d)", (int)getpid());
		return false;
	}

	cap_t cap_new = cap_dup(cap_orig);
	if (cap_new == NULL) {
		PLOG_W("cap_dup()");
		cap_free(cap_orig);
		return false;
	}

	struct capslistt *l = is_global ? &nsjconf->global_caps : &nsjconf->local_caps;
	if (is_global || nsjconf->keep_caps == false) {
		if (cap_clear_flag(cap_new, CAP_INHERITABLE) == -1) {
			PLOG_W("cap_clear_flag(CAP_INHERITABLE)");
			cap_free(cap_orig);
			cap_free(cap_new);
			return false;
		}
		if (is_global == false) {
			if (cap_clear_flag(cap_new, CAP_PERMITTED) == -1) {
				PLOG_W("cap_clear_flag(CAP_PERMITTED)");
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
			if (cap_clear_flag(cap_new, CAP_EFFECTIVE) == -1) {
				PLOG_W("cap_clear_flag(CAP_EFFECTIVE)");
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
		}

		struct ints_t *p;
		TAILQ_FOREACH(p, l, pointers) {
			cap_flag_value_t v;
			if (cap_get_flag(cap_orig, p->val, CAP_PERMITTED, &v) == -1) {
				PLOG_W("cap_get_flag(cap_orig, CAP_PERMITTED, %s)",
				       capsValToStr(p->val));
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
			if (v != CAP_SET) {
				LOG_W("Capability %s is not permitted in the %s namespace",
				      capsValToStr(p->val), is_global ? "global" : "local");
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
			if (cap_set_flag(cap_new, CAP_INHERITABLE, 1, &p->val, CAP_SET) == -1) {
				PLOG_W("cap_set_flag(cap_new, CAP_INHERITABLE, %s)",
				       capsValToStr(p->val));
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
			if (is_global == false) {
				if (cap_set_flag(cap_new, CAP_PERMITTED, 1, &p->val, CAP_SET) == -1) {
					PLOG_W("cap_set_flag(cap_new, CAP_PERMITTED, %s)",
					       capsValToStr(p->val));
					cap_free(cap_orig);
					cap_free(cap_new);
					return false;
				}
				if (cap_set_flag(cap_new, CAP_EFFECTIVE, 1, &p->val, CAP_SET) == -1) {
					PLOG_W("cap_set_flag(cap_new, CAP_EFFECTIVE, %s)",
					       capsValToStr(p->val));
					cap_free(cap_orig);
					cap_free(cap_new);
					return false;
				}
			}
		}
	}

	if (is_global == false || nsjconf->keep_caps == true) {
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			cap_flag_value_t v;
			if (cap_get_flag(cap_orig, capNames[i].val, CAP_PERMITTED, &v) == -1) {
				PLOG_W("cap_get_flag(cap_orig, CAP_PERMITTED, %s)",
				       capNames[i].name);
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
			if (cap_set_flag(cap_new, CAP_INHERITABLE, 1, &capNames[i].val, v) == -1) {
				PLOG_W("cap_set_flag(cap_new, CAP_INHERITABLE, %s)",
				       capNames[i].name);
				cap_free(cap_orig);
				cap_free(cap_new);
				return false;
			}
		}
	}

	if (cap_set_proc(cap_new) == -1) {
		PLOG_W("cap_set_proc()");
		cap_free(cap_orig);
		cap_free(cap_new);
		return false;
	}
#if defined(PR_CAP_AMBIENT)
	if (is_global == false && nsjconf->keep_caps == true) {
		for (unsigned long i = 0; i < CAP_LAST_CAP; i++) {
			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0UL, 0UL) == -1) {
				PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
				       capsValToStr(i));
			}
		}
	} else {
		struct ints_t *p;
		TAILQ_FOREACH(p, l, pointers) {
			if (prctl
			    (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)p->val, 0UL,
			     0UL) == -1) {
				PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
				       capsValToStr(p->val));
			}
		}
	}
#endif				/* defined(PR_CAP_AMBIENT) */

	cap_free(cap_orig);
	cap_free(cap_new);
	return true;
}

bool capsInitGlobalNs(struct nsjconf_t * nsjconf)
{
	return capsInitInternal(nsjconf, true /* global */ );
}

bool capsInitLocalNs(struct nsjconf_t * nsjconf)
{
	return capsInitInternal(nsjconf, false /* local */ );
}
