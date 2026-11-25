/*

   nsjail - optional Landlock filesystem layer
   -----------------------------------------

   Copyright 2026 Google Inc. All Rights Reserved.

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

#include "landlock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "logs.h"
#include "util.h"

/*
 * The Landlock UAPI is declared locally: the syscall numbers and structures are a stable kernel
 * ABI, and older distro headers lack the ABI 3+ access rights.
 */
#if !defined(__NR_landlock_create_ruleset)
#define __NR_landlock_create_ruleset 444
#endif
#if !defined(__NR_landlock_add_rule)
#define __NR_landlock_add_rule 445
#endif
#if !defined(__NR_landlock_restrict_self)
#define __NR_landlock_restrict_self 446
#endif

namespace landlock {

namespace {

constexpr uint32_t kCreateRulesetVersion = 1U << 0;
constexpr int kRulePathBeneath = 1;

constexpr uint64_t kAccessExecute = 1ULL << 0;
constexpr uint64_t kAccessWriteFile = 1ULL << 1;
constexpr uint64_t kAccessReadFile = 1ULL << 2;
constexpr uint64_t kAccessReadDir = 1ULL << 3;
constexpr uint64_t kAccessRemoveDir = 1ULL << 4;
constexpr uint64_t kAccessRemoveFile = 1ULL << 5;
constexpr uint64_t kAccessMakeChar = 1ULL << 6;
constexpr uint64_t kAccessMakeDir = 1ULL << 7;
constexpr uint64_t kAccessMakeReg = 1ULL << 8;
constexpr uint64_t kAccessMakeSock = 1ULL << 9;
constexpr uint64_t kAccessMakeFifo = 1ULL << 10;
constexpr uint64_t kAccessMakeBlock = 1ULL << 11;
constexpr uint64_t kAccessMakeSym = 1ULL << 12;
constexpr uint64_t kAccessRefer = 1ULL << 13;	 /* ABI 2 */
constexpr uint64_t kAccessTruncate = 1ULL << 14; /* ABI 3 */
constexpr uint64_t kAccessIoctlDev = 1ULL << 15; /* ABI 5 */

struct RulesetAttr {
	uint64_t handled_access_fs;
};

struct __attribute__((packed)) PathBeneathAttr {
	uint64_t allowed_access;
	int32_t parent_fd;
};

/* Access rights that can be requested for a regular file (not a directory). */
constexpr uint64_t kFileOnlyAccess =
    kAccessExecute | kAccessWriteFile | kAccessReadFile | kAccessTruncate | kAccessIoctlDev;

std::string mountDst(const nsjail::MountPt& mpt) {
	std::string dst;
	if (!mpt.prefix_dst_env().empty()) {
		const char* env = getenv(mpt.prefix_dst_env().c_str());
		if (env == nullptr) {
			return "";
		}
		dst = env;
	}
	return dst + mpt.dst();
}

bool failOrWarn(nsj_t* nsj, const char* what) {
	if (nsj->njc.landlock() == nsjail::LANDLOCK_REQUIRED) {
		PLOG_E("Landlock: %s", what);
		return false;
	}
	PLOG_W("Landlock: %s (continuing without it, landlock=BEST_EFFORT)", what);
	return true;
}

}  // namespace

uint64_t handledAccessForAbi(int abi) {
	uint64_t handled = kAccessExecute | kAccessWriteFile | kAccessReadFile | kAccessReadDir |
			   kAccessRemoveDir | kAccessRemoveFile | kAccessMakeChar | kAccessMakeDir |
			   kAccessMakeReg | kAccessMakeSock | kAccessMakeFifo | kAccessMakeBlock |
			   kAccessMakeSym;
	if (abi >= 2) {
		handled |= kAccessRefer;
	}
	if (abi >= 3) {
		handled |= kAccessTruncate;
	}
	if (abi >= 5) {
		handled |= kAccessIoctlDev;
	}
	return handled;
}

uint64_t accessForMount(const nsjail::MountPt& mpt, bool is_dir, uint64_t handled) {
	bool rw = mpt.rw();
	bool noexec = mpt.noexec();
	if (!mpt.options().empty()) {
		for (const auto& opt : util::strSplit(mpt.options(), ',')) {
			if (opt == "ro") {
				rw = false;
			} else if (opt == "rw") {
				rw = true;
			} else if (opt == "noexec") {
				noexec = true;
			} else if (opt == "exec") {
				noexec = false;
			}
		}
	}

	uint64_t access = kAccessReadFile | kAccessReadDir;
	if (!noexec) {
		access |= kAccessExecute;
	}
	if (rw) {
		access |= kAccessWriteFile | kAccessRemoveDir | kAccessRemoveFile |
			  kAccessMakeChar | kAccessMakeDir | kAccessMakeReg | kAccessMakeSock |
			  kAccessMakeFifo | kAccessMakeBlock | kAccessMakeSym | kAccessRefer |
			  kAccessTruncate | kAccessIoctlDev;
	}
	if (!is_dir) {
		access &= kFileOnlyAccess;
	}
	return access & handled;
}

bool apply(nsj_t* nsj) {
	if (nsj->njc.landlock() == nsjail::LANDLOCK_OFF) {
		return true;
	}

	long abi = util::syscall(__NR_landlock_create_ruleset, 0, 0, kCreateRulesetVersion);
	if (abi < 1) {
		return failOrWarn(nsj, "the kernel does not support Landlock");
	}
	const uint64_t handled = handledAccessForAbi((int)abi);
	LOG_D("Landlock ABI version: %ld, handled fs access: 0x%llx", abi,
	    (unsigned long long)handled);

	RulesetAttr attr = {.handled_access_fs = handled};
	int ruleset_fd =
	    (int)util::syscall(__NR_landlock_create_ruleset, (uintptr_t)&attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		return failOrWarn(nsj, "landlock_create_ruleset() failed");
	}

	bool ok = true;
	for (const auto& mpt : nsj->njc.mount()) {
		if (mpt.is_symlink()) {
			continue;
		}
		const std::string dst = mountDst(mpt);
		if (dst.empty()) {
			continue;
		}
		int fd = TEMP_FAILURE_RETRY(open(dst.c_str(), O_PATH | O_CLOEXEC));
		if (fd < 0) {
			/* Not present in the jail (e.g. a non-mandatory mount that failed). */
			PLOG_W("Landlock: skipping rule for %s", QC(dst));
			continue;
		}
		struct stat st;
		bool is_dir = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
		PathBeneathAttr rule = {
		    .allowed_access = accessForMount(mpt, is_dir, handled),
		    .parent_fd = fd,
		};
		long rv = util::syscall(
		    __NR_landlock_add_rule, ruleset_fd, kRulePathBeneath, (uintptr_t)&rule, 0);
		close(fd);
		if (rv != 0) {
			PLOG_E("landlock_add_rule(%s)", QC(dst));
			ok = false;
			break;
		}
	}

	if (ok && util::syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
		ok = failOrWarn(nsj, "landlock_restrict_self() failed (is no_new_privs enabled?)");
	}
	close(ruleset_fd);
	return ok;
}

}  // namespace landlock
