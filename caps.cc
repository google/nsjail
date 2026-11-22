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

#include <array>
#include <cerrno>
#include <string>

#include "logs.h"
#include "macros.h"
#include "util.h"

#if !defined(CAP_AUDIT_READ)
#define CAP_AUDIT_READ 37
#endif /* !defined(CAP_AUDIT_READ) */
#if !defined(CAP_PERFMON)
#define CAP_PERFMON 38
#endif /* !defined(CAP_PERFMON) */
#if !defined(CAP_BPF)
#define CAP_BPF 39
#endif /* !defined(CAP_BPF) */
#if !defined(CAP_CHECKPOINT_RESTORE)
#define CAP_CHECKPOINT_RESTORE 40
#endif /* !defined(CAP_CHECKPOINT_RESTORE) */

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
    NS_VALSTR_STRUCT(CAP_AUDIT_READ),
    NS_VALSTR_STRUCT(CAP_PERFMON),
    NS_VALSTR_STRUCT(CAP_BPF),
    NS_VALSTR_STRUCT(CAP_CHECKPOINT_RESTORE),
};

int nameToVal(const char* name) {
	for (const auto& cap : capNames) {
		if (util::StrEq(name, cap.name)) {
			return cap.val;
		}
	}
	LOG_W("Unknown capability: '%s'", name);
	return -1;
}

static const std::string capToStr(int val) {
	for (const auto& cap : capNames) {
		if (val == cap.val) {
			return cap.name;
		}
	}

	std::string res;
	res.append("CAP_UNKNOWN(").append(std::to_string(val)).append(")");
	return res;
}

/* The capability sets, as exchanged with capget()/capset() for _LINUX_CAPABILITY_VERSION_3 */
using CapData = std::array<struct __user_cap_data_struct, _LINUX_CAPABILITY_U32S_3>;

static bool getCaps(CapData* cap_data) {
	const struct __user_cap_header_struct cap_hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	*cap_data = {};
	if (util::syscall(__NR_capget, (uintptr_t)&cap_hdr, (uintptr_t)cap_data->data()) == -1) {
		PLOG_W("capget() failed");
		return false;
	}
	return true;
}

static bool setCaps(const CapData& cap_data) {
	const struct __user_cap_header_struct cap_hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	if (util::syscall(__NR_capset, (uintptr_t)&cap_hdr, (uintptr_t)cap_data.data()) == -1) {
		PLOG_W("capset() failed");
		return false;
	}
	return true;
}

static void clearInheritable(CapData* cap_data) {
	for (auto& data : *cap_data) {
		data.inheritable = 0U;
	}
}

/*
 * Returns the element of 'cap_data' which holds the bit of 'cap', or nullptr if 'cap' is
 * outside of the capability sets passed to capget()/capset().
 */
static const struct __user_cap_data_struct* capEntry(const CapData& cap_data, unsigned int cap) {
	size_t idx = CAP_TO_INDEX(cap);
	if (idx >= cap_data.size()) {
		LOG_W("Capability %u is out of range of the capability sets", cap);
		return nullptr;
	}
	return &cap_data[idx];
}

static bool getPermitted(const CapData& cap_data, unsigned int cap) {
	const auto* entry = capEntry(cap_data, cap);
	return entry != nullptr && (entry->permitted & CAP_TO_MASK(cap));
}

static bool getEffective(const CapData& cap_data, unsigned int cap) {
	const auto* entry = capEntry(cap_data, cap);
	return entry != nullptr && (entry->effective & CAP_TO_MASK(cap));
}

static bool getInheritable(const CapData& cap_data, unsigned int cap) {
	const auto* entry = capEntry(cap_data, cap);
	return entry != nullptr && (entry->inheritable & CAP_TO_MASK(cap));
}

static bool setInheritable(CapData* cap_data, unsigned int cap) {
	if (capEntry(*cap_data, cap) == nullptr) {
		return false;
	}
	(*cap_data)[CAP_TO_INDEX(cap)].inheritable |= CAP_TO_MASK(cap);
	return true;
}

#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif /* !defined(PR_CAP_AMBIENT) */
static bool initNsKeepCaps(CapData* cap_data) {
	/* Copy all permitted caps to the inheritable set */
	std::string dbgmsg1;
	for (const auto& i : capNames) {
		if (getPermitted(*cap_data, i.val)) {
			util::StrAppend(&dbgmsg1, " %s", i.name);
			setInheritable(cap_data, i.val);
		}
	}
	LOG_D("Adding the following capabilities to the inheritable set:%s", dbgmsg1.c_str());

	if (!setCaps(*cap_data)) {
		return false;
	}

	/* Make sure the inheritable set is preserved across execve via the ambient set */
	std::string dbgmsg2;
	for (const auto& i : capNames) {
		if (!getPermitted(*cap_data, i.val)) {
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

bool initNs(nsj_t* nsj) {
	CapData cap_data;
	if (!getCaps(&cap_data)) {
		return false;
	}

	/* Let's start with an empty inheritable set to avoid any mistakes */
	clearInheritable(&cap_data);
	/*
	 * Remove all capabilities from the ambient set first. It works with newer kernel versions
	 * only, so don't panic() if it fails
	 */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL) == -1) {
		PLOG_W("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)");
	}

	if (nsj->njc.keep_caps()) {
		return initNsKeepCaps(&cap_data);
	}

	/* Set all requested caps in the inheritable set if these are present in the permitted set
	 */
	std::string dbgmsg;
	for (ssize_t i = 0; i < nsj->njc.cap_size(); i++) {
		int cap = nameToVal(nsj->njc.cap(i).c_str());
		if (cap == -1) {
			LOG_W("Unknown capability: %s", nsj->njc.cap(i).c_str());
			continue;
		}
		if (!getPermitted(cap_data, cap)) {
			LOG_W("Capability %s is not permitted in the namespace",
			    capToStr(cap).c_str());
			return false;
		}
		if (!setInheritable(&cap_data, cap)) {
			return false;
		}
		dbgmsg.append(" ").append(capToStr(cap));
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
			if (prctl(PR_CAPBSET_READ, (unsigned long)i.val, 0UL, 0UL, 0UL) == -1 &&
			    errno == EINVAL) {
				LOG_D("Skipping unsupported capability: %s", i.name);
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
	for (ssize_t i = 0; i < nsj->njc.cap_size(); i++) {
		int cap = nameToVal(nsj->njc.cap(i).c_str());
		if (cap == -1) {
			continue;
		}
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
