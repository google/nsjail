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

#include <linux/capability.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

#define VALSTR_STRUCT(x) \
    {                    \
        x, #x            \
    }

#if !defined(CAP_AUDIT_READ)
#define CAP_AUDIT_READ 37
#endif				/* !defined(CAP_AUDIT_READ) */

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

static cap_user_data_t capsGet()
{
	static __thread struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3];
	const struct __user_cap_header_struct cap_hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	if (syscall(__NR_capget, &cap_hdr, &cap_data) == -1) {
		PLOG_W("capget() failed");
		return NULL;
	}
	return cap_data;
}

static bool capsSet(const cap_user_data_t cap_data)
{
	const struct __user_cap_header_struct cap_hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	if (syscall(__NR_capset, &cap_hdr, cap_data) == -1) {
		PLOG_W("capset() failed");
		return false;
	}
	return true;
}

static void capsClearInheritable(cap_user_data_t cap_data)
{
	for (size_t i = 0; i < _LINUX_CAPABILITY_U32S_3; i++) {
		cap_data[i].inheritable = 0U;
	}
}

static bool capsGetPermitted(cap_user_data_t cap_data, unsigned int cap)
{
	size_t off_byte = cap / (sizeof(cap_data->permitted) * 8);
	size_t off_bit = cap % (sizeof(cap_data->permitted) * 8);
	return cap_data[off_byte].permitted & (1U << off_bit);
}

static bool capsGetEffective(cap_user_data_t cap_data, unsigned int cap)
{
	size_t off_byte = cap / (sizeof(cap_data->effective) * 8);
	size_t off_bit = cap % (sizeof(cap_data->effective) * 8);
	return cap_data[off_byte].effective & (1U << off_bit);
}

static bool capsGetInheritable(cap_user_data_t cap_data, unsigned int cap)
{
	size_t off_byte = cap / (sizeof(cap_data->inheritable) * 8);
	size_t off_bit = cap % (sizeof(cap_data->inheritable) * 8);
	return cap_data[off_byte].inheritable & (1U << off_bit);
}

static void capsSetInheritable(cap_user_data_t cap_data, unsigned int cap)
{
	size_t off_byte = cap / (sizeof(cap_data->inheritable) * 8);
	size_t off_bit = cap % (sizeof(cap_data->inheritable) * 8);
	cap_data[off_byte].inheritable |= (1U << off_bit);
}

#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif				/* !defined(PR_CAP_AMBIENT) */
static bool CapsInitNsKeepCaps(cap_user_data_t cap_data)
{
	char dbgmsg[4096];

	/* Copy all permitted caps to the inheritable set */
	dbgmsg[0] = '\0';
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (capsGetPermitted(cap_data, capNames[i].val) == true) {
			utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
			capsSetInheritable(cap_data, capNames[i].val);
		}
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg);

	if (capsSet(cap_data) == false) {
		return false;
	}

	/* Make sure the inheritable set is preserved across execve via the ambient set */
	dbgmsg[0] = '\0';
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (capsGetPermitted(cap_data, capNames[i].val) == false) {
			continue;
		}
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)capNames[i].val, 0UL,
			  0UL)
		    == -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)", capNames[i].name);
		} else {
			utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg);

	return true;
}

bool capsInitNs(struct nsjconf_t * nsjconf)
{
	char dbgmsg[4096];
	struct ints_t *p;

	cap_user_data_t cap_data = capsGet();
	if (cap_data == NULL) {
		return false;
	}
	/* Let's start with the empty inheritable set to avoid any mistakes */
	capsClearInheritable(cap_data);

	if (nsjconf->keep_caps) {
		return CapsInitNsKeepCaps(cap_data);
	}

	/* Set all requested caps in the inheritable set if these are present in the permitted set */
	dbgmsg[0] = '\0';
	TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
		if (capsGetPermitted(cap_data, p->val) == false) {
			LOG_W("Capability %s is not permitted in the namespace",
			      capsValToStr(p->val));
			return false;
		}
		utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capsValToStr(p->val));
		capsSetInheritable(cap_data, p->val);
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg);

	if (capsSet(cap_data) == false) {
		return false;
	}

	/*
	 * Make sure all other caps (those which were not explicitly requested) are removed from the
	 * bounding set
	 */
	if (capsGetEffective(cap_data, CAP_SETPCAP) == true) {
		dbgmsg[0] = '\0';
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			if (capsGetInheritable(cap_data, capNames[i].val) == true) {
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
	}

	/* Make sure inheritable set is preserved across execve via the modified ambient set */
	dbgmsg[0] = '\0';
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL) == -1) {
		PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)");
	}
	TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)p->val, 0UL, 0UL) ==
		    -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
			       capsValToStr(p->val));
		} else {
			utilSSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capsValToStr(p->val));
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg);

	return true;
}
