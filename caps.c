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
#include "util.h"

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
#if defined(CAP_AUDIT_READ)
    VALSTR_STRUCT(CAP_AUDIT_READ),
#endif  /* defined(CAP_AUDIT_READ) */
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

static cap_t capsGet(void)
{
	cap_t cap = cap_get_pid(getpid());
	if (cap == NULL) {
		PLOG_F("cap_get_pit(PID=%d)", (int)getpid());
	}
	return cap;
}

static void capsFree(cap_t cap)
{
	if (cap_free(cap) == -1) {
		PLOG_F("cap_free()");
	}
}

static void capsClearType(cap_t cap, cap_flag_t type)
{
	if (cap_clear_flag(cap, type) == -1) {
		PLOG_F("cap_clear_flag(flag=%d)", (int)type);
	}
}

static cap_flag_value_t capsGetCap(cap_t cap, cap_value_t id, cap_flag_t type)
{
	cap_flag_value_t v;
	if (cap_get_flag(cap, id, type, &v) == -1) {
#if defined(CAP_AUDIT_READ)
		if (id == CAP_AUDIT_READ) {
			PLOG_W
			    ("CAP_AUDIT_READ requested to be read but your libcap doesn't understand this capability");
			return CAP_CLEAR;
		}
#endif
		PLOG_F("cap_get_flag(id=%s, type=%d)", capsValToStr((int)id), (int)type);
	}
	return v;
}

static void capsSetCap(cap_t cap, cap_value_t id, cap_value_t type, cap_flag_value_t val)
{
	if (cap_set_flag(cap, type, 1, &id, val) == -1) {
#if defined(CAP_AUDIT_READ)
		if (id == CAP_AUDIT_READ) {
			PLOG_W
			    ("CAP_AUDIT_READ requested to be set but your libcap doesn't understand this capability");
			return;
		}
#endif
		PLOG_F("cap_set_flag(id=%s, type=%d, val=%d)", capsValToStr((int)id), (int)type,
		       (int)val);
	}
}

bool capsInitNs(struct nsjconf_t *nsjconf)
{
	cap_t cap_orig = capsGet();
	cap_t cap_new = capsGet();

	char dbgmsg[4096];
	dbgmsg[0] = '\0';

	if (nsjconf->keep_caps) {
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			cap_flag_value_t v = capsGetCap(cap_orig, capNames[i].val, CAP_PERMITTED);
			if (v == CAP_SET) {
				utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
			}
			capsSetCap(cap_new, capNames[i].val, CAP_INHERITABLE, v);
		}
	} else {
		capsClearType(cap_new, CAP_INHERITABLE);
		struct ints_t *p;
		TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
			if (capsGetCap(cap_orig, p->val, CAP_PERMITTED) != CAP_SET) {
				LOG_W("Capability %s is not permitted in the namespace",
				      capsValToStr(p->val));
				capsFree(cap_orig);
				capsFree(cap_new);
				return false;
			}
			utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capsValToStr(p->val));
			capsSetCap(cap_new, p->val, CAP_INHERITABLE, CAP_SET);
		}
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg);
	dbgmsg[0] = '\0';

	if (cap_set_proc(cap_new) == -1) {
		capsFree(cap_orig);
		capsFree(cap_new);
		return false;
	}
#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif				/* !defined(PR_CAP_AMBIENT) */
	if (nsjconf->keep_caps) {
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			if (capsGetCap(cap_orig, capNames[i].val, CAP_PERMITTED) != CAP_SET) {
				continue;
			}
			if (prctl
			    (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)capNames[i].val,
			     0UL, 0UL) == -1) {
				PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
				       capNames[i].name);
			} else {
				utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
			}
		}
	} else {
		struct ints_t *p;
		TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
			if (prctl
			    (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)p->val, 0UL,
			     0UL) == -1) {
				PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
				       capsValToStr(p->val));
			} else {
				utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capsValToStr(p->val));
			}
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg);
	dbgmsg[0] = '\0';

	if (nsjconf->keep_caps == false) {
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			if (capsGetCap(cap_new, capNames[i].val, CAP_INHERITABLE) == CAP_SET) {
				continue;
			}
			utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
			if (prctl(PR_CAPBSET_DROP, (unsigned long)capNames[i].val, 0UL, 0UL, 0UL) ==
			    -1) {
				PLOG_W("prctl(PR_CAPBSET_DROP, %s)", capNames[i].name);
				return false;
			}
		}
		LOG_D("Dropped the following capabilities from the bounding set:%s", dbgmsg);
		dbgmsg[0] = '\0';
	}

	capsFree(cap_orig);
	capsFree(cap_new);
	return true;
}
