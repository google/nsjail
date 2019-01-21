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

#include <string>

#include "logs.h"
#include "macros.h"
#include "util.h"

namespace caps {

struct {
	const int val;
	const char* const name;
} static const capNames[] = {
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
	for (const auto& cap : capNames) {
		if (strcmp(name, cap.name) == 0) {
			return cap.val;
		}
	}
	LOG_W("Uknown capability: '%s'", name);
	return -1;
}

static const std::string capToStr(int val) {
	for (const auto& cap : capNames) {
		if (val == cap.val) {
			return cap.name;
		}
	}

	std::string res;
	res.append("CAP_UNKNOWN(");
	res.append(std::to_string(val));
	res.append(")");
	return res;
}

static cap_user_data_t getCaps() {
	static __thread struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3];
	const struct __user_cap_header_struct cap_hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	if (util::syscall(__NR_capget, (uintptr_t)&cap_hdr, (uintptr_t)&cap_data) == -1) {
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
	if (util::syscall(__NR_capset, (uintptr_t)&cap_hdr, (uintptr_t)cap_data) == -1) {
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
	size_t off_byte = CAP_TO_INDEX(cap);
	unsigned mask = CAP_TO_MASK(cap);
	return cap_data[off_byte].permitted & mask;
}

static bool getEffective(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = CAP_TO_INDEX(cap);
	unsigned mask = CAP_TO_MASK(cap);
	return cap_data[off_byte].effective & mask;
}

static bool getInheritable(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = CAP_TO_INDEX(cap);
	unsigned mask = CAP_TO_MASK(cap);
	return cap_data[off_byte].inheritable & mask;
}

static void setInheritable(cap_user_data_t cap_data, unsigned int cap) {
	size_t off_byte = CAP_TO_INDEX(cap);
	unsigned mask = CAP_TO_MASK(cap);
	cap_data[off_byte].inheritable |= mask;
}

#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif /* !defined(PR_CAP_AMBIENT) */
static bool initNsKeepCaps(cap_user_data_t cap_data) {
	/* Copy all permitted caps to the inheritable set */
	std::string dbgmsg1;
	for (const auto& i : capNames) {
		if (getPermitted(cap_data, i.val)) {
			util::StrAppend(&dbgmsg1, " %s", i.name);
			setInheritable(cap_data, i.val);
		}
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg1.c_str());

	if (!setCaps(cap_data)) {
		return false;
	}

	/* Make sure the inheritable set is preserved across execve via the ambient set */
	std::string dbgmsg2;
	for (const auto& i : capNames) {
		if (!getPermitted(cap_data, i.val)) {
			continue;
		}
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)i.val, 0UL, 0UL) ==
		    -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)", i.name);
		} else {
			util::StrAppend(&dbgmsg2, " %s", i.name);
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg2.c_str());

	return true;
}

bool initNs(nsjconf_t* nsjconf) {
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
	std::string dbgmsg;
	for (const auto& cap : nsjconf->caps) {
		if (!getPermitted(cap_data, cap)) {
			LOG_W("Capability %s is not permitted in the namespace",
			    capToStr(cap).c_str());
			return false;
		}
		dbgmsg.append(" ").append(capToStr(cap));
		setInheritable(cap_data, cap);
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg.c_str());

	if (!setCaps(cap_data)) {
		return false;
	}

	/*
	 * Make sure all other caps (those which were not explicitly requested) are removed from the
	 * bounding set. We need to have CAP_SETPCAP to do that now
	 */
	dbgmsg.clear();
	if (getEffective(cap_data, CAP_SETPCAP)) {
		for (const auto& i : capNames) {
			if (getInheritable(cap_data, i.val)) {
				continue;
			}
			dbgmsg.append(" ").append(i.name);
			if (prctl(PR_CAPBSET_DROP, (unsigned long)i.val, 0UL, 0UL, 0UL) == -1) {
				PLOG_W("prctl(PR_CAPBSET_DROP, %s)", i.name);
				return false;
			}
		}
		LOG_D(
		    "Dropped the following capabilities from the bounding set:%s", dbgmsg.c_str());
	}

	/* Make sure inheritable set is preserved across execve via the modified ambient set */
	dbgmsg.clear();
	for (const auto& cap : nsjconf->caps) {
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)cap, 0UL, 0UL) ==
		    -1) {
			PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %s)",
			    capToStr(cap).c_str());
		} else {
			dbgmsg.append(" ").append(capToStr(cap));
		}
	}
	LOG_D("Added the following capabilities to the ambient set:%s", dbgmsg.c_str());

	return true;
}

}  // namespace caps
