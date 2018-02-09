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

extern "C" {
#include "log.h"
}

#include "common.h"
#include "util.h"

namespace caps {

static struct {
	const int val;
	const char* const name;
} const capNames[] = {
    NS_VALSTR_STRUCT(CAP_CHOWN),
    NS_VALSTR_STRUCT(CAP_DAC_OVERRIDE),
    NS_VALSTR_STRUCT(CAP_DAC_READ_SEARCH),
    NS_VALSTR_STRUCT(CAP_FOWNER),
    NS_VALSTR_STRUCT(CAP_FSETID),
    NS_VALSTR_STRUCT(CAP_KILL),
    NS_VALSTR_STRUCT(CAP_SETGID),
    NS_VALSTR_STRUCT(CAP_SETUID),
    NS_VALSTR_STRUCT(CAP_SETPCAP),
    NS_VALSTR_STRUCT(CAP_LINUX_IMMUTABLE),
    NS_VALSTR_STRUCT(CAP_NET_BIND_SERVICE),
    NS_VALSTR_STRUCT(CAP_NET_BROADCAST),
    NS_VALSTR_STRUCT(CAP_NET_ADMIN),
    NS_VALSTR_STRUCT(CAP_NET_RAW),
    NS_VALSTR_STRUCT(CAP_IPC_LOCK),
    NS_VALSTR_STRUCT(CAP_IPC_OWNER),
    NS_VALSTR_STRUCT(CAP_SYS_MODULE),
    NS_VALSTR_STRUCT(CAP_SYS_RAWIO),
    NS_VALSTR_STRUCT(CAP_SYS_CHROOT),
    NS_VALSTR_STRUCT(CAP_SYS_PTRACE),
    NS_VALSTR_STRUCT(CAP_SYS_PACCT),
    NS_VALSTR_STRUCT(CAP_SYS_ADMIN),
    NS_VALSTR_STRUCT(CAP_SYS_BOOT),
    NS_VALSTR_STRUCT(CAP_SYS_NICE),
    NS_VALSTR_STRUCT(CAP_SYS_RESOURCE),
    NS_VALSTR_STRUCT(CAP_SYS_TIME),
    NS_VALSTR_STRUCT(CAP_SYS_TTY_CONFIG),
    NS_VALSTR_STRUCT(CAP_MKNOD),
    NS_VALSTR_STRUCT(CAP_LEASE),
    NS_VALSTR_STRUCT(CAP_AUDIT_WRITE),
    NS_VALSTR_STRUCT(CAP_AUDIT_CONTROL),
    NS_VALSTR_STRUCT(CAP_SETFCAP),
    NS_VALSTR_STRUCT(CAP_MAC_OVERRIDE),
    NS_VALSTR_STRUCT(CAP_MAC_ADMIN),
    NS_VALSTR_STRUCT(CAP_SYSLOG),
    NS_VALSTR_STRUCT(CAP_WAKE_ALARM),
    NS_VALSTR_STRUCT(CAP_BLOCK_SUSPEND),
#if defined(CAP_AUDIT_READ)
    NS_VALSTR_STRUCT(CAP_AUDIT_READ),
#endif /* defined(CAP_AUDIT_READ) */
};

int nameToVal(const char* name) {
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (strcmp(name, capNames[i].name) == 0) {
			return capNames[i].val;
		}
	}
	LOG_W("Uknown capability: '%s'", name);
	return -1;
}

static const char* valToStr(int val) {
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

static cap_user_data_t getCaps() {
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

static bool setCaps(const cap_user_data_t cap_data) {
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

static void clearInheritable(cap_user_data_t cap_data) {
	for (size_t i = 0; i < _LINUX_CAPABILITY_U32S_3; i++) {
		cap_data[i].inheritable = 0U;
	}
}

static bool getPermitted(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = cap / (sizeof(cap_data->permitted) * 8);
	size_t off_bit = cap % (sizeof(cap_data->permitted) * 8);
	return cap_data[off_byte].permitted & (1U << off_bit);
}

static bool getEffective(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = cap / (sizeof(cap_data->effective) * 8);
	size_t off_bit = cap % (sizeof(cap_data->effective) * 8);
	return cap_data[off_byte].effective & (1U << off_bit);
}

static bool getInheritable(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = cap / (sizeof(cap_data->inheritable) * 8);
	size_t off_bit = cap % (sizeof(cap_data->inheritable) * 8);
	return cap_data[off_byte].inheritable & (1U << off_bit);
}

static void setInheritable(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = cap / (sizeof(cap_data->inheritable) * 8);
	size_t off_bit = cap % (sizeof(cap_data->inheritable) * 8);
	cap_data[off_byte].inheritable |= (1U << off_bit);
}

#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif /* !defined(PR_CAP_AMBIENT) */
static bool initNsKeepCaps(cap_user_data_t cap_data) {
	char dbgmsg[4096];

	/* Copy all permitted caps to the inheritable set */
	dbgmsg[0] = '\0';
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (getPermitted(cap_data, capNames[i].val)) {
			util::sSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
			setInheritable(cap_data, capNames[i].val);
		}
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg);

	if (setCaps(cap_data) == false) {
		return false;
	}

	/* Make sure the inheritable set is preserved across execve via the ambient set */
	dbgmsg[0] = '\0';
	for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
		if (getPermitted(cap_data, capNames[i].val) == false) {
			continue;
		}
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)capNames[i].val, 0UL,
			0UL) == -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)", capNames[i].name);
		} else {
			util::sSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg);

	return true;
}

bool initNs(struct nsjconf_t* nsjconf) {
	char dbgmsg[4096];
	struct ints_t* p;

	cap_user_data_t cap_data = getCaps();
	if (cap_data == NULL) {
		return false;
	}

	/* Let's start with an empty inheritable set to avoid any mistakes */
	clearInheritable(cap_data);
	/*
	 * Remove all capabilities from the ambient set first. It works with newer kernel versions
	 * only, so don't panic() if it fails
	 */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL) == -1) {
		PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)");
	}

	if (nsjconf->keep_caps) {
		return initNsKeepCaps(cap_data);
	}

	/* Set all requested caps in the inheritable set if these are present in the permitted set
	 */
	dbgmsg[0] = '\0';
	TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
		if (getPermitted(cap_data, p->val) == false) {
			LOG_W("Capability %s is not permitted in the namespace", valToStr(p->val));
			return false;
		}
		util::sSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", valToStr(p->val));
		setInheritable(cap_data, p->val);
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg);

	if (setCaps(cap_data) == false) {
		return false;
	}

	/*
	 * Make sure all other caps (those which were not explicitly requested) are removed from the
	 * bounding set. We need to have CAP_SETPCAP to do that now
	 */
	if (getEffective(cap_data, CAP_SETPCAP)) {
		dbgmsg[0] = '\0';
		for (size_t i = 0; i < ARRAYSIZE(capNames); i++) {
			if (getInheritable(cap_data, capNames[i].val)) {
				continue;
			}
			util::sSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", capNames[i].name);
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
	TAILQ_FOREACH(p, &nsjconf->caps, pointers) {
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)p->val, 0UL, 0UL) ==
		    -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)", valToStr(p->val));
		} else {
			util::sSnPrintf(dbgmsg, sizeof(dbgmsg), " %s", valToStr(p->val));
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg);

	return true;
}

}  // namespace caps
