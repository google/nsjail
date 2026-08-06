/*

   nsjail - CLONE_NEWNS routines
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

#ifndef NS_MNT_H
#define NS_MNT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/statvfs.h>

#include <string>

#include "nsjail.h"

#if !defined(MS_NOSYMFOLLOW)
#define MS_NOSYMFOLLOW 256
#endif /* if !defined(MS_NOSYMFOLLOW) */

#if !defined(MS_LAZYTIME)
#define MS_LAZYTIME (1 << 25)
#endif /* if !defined(MS_LAZYTIME) */

#if !defined(MS_ACTIVE)
#define MS_ACTIVE (1 << 30)
#endif /* if !defined(MS_ACTIVE) */

#if !defined(MS_NOUSER)
#define MS_NOUSER (1 << 31)
#endif /* if !defined(MS_NOUSER) */

#if !defined(ST_NOSYMFOLLOW)
#define ST_NOSYMFOLLOW 8192
#endif /* if !defined(ST_NOSYMFOLLOW) */

namespace mnt {

typedef enum {
	NS_DIR_NO = 0x100,
	NS_DIR_YES,
	NS_DIR_MAYBE,
} isDir_t;

struct mount_identity_t {
	bool valid;
	bool has_mount_id;
	uint64_t ino;
	uint64_t mnt_id;
	dev_t dev;
	mode_t type;
};

/* Shared mount point structure used by both legacy and new API */
struct mount_t {
	const nsjail::MountPt* mpt;
	std::string src;
	std::string dst;
	uintptr_t flags;
	bool is_dir;
	bool mounted;
	int fd; /* Used by new mount API for deferred remount */
	mount_identity_t identity;
};

struct resolved_dst_t {
	int dirfd;
	std::string leaf;
	bool is_root;
};

bool initNs(nsj_t* nsj);
std::unique_ptr<std::string> findWorkDir(nsj_t* nsj, const char* purpose);
const std::string describeMountPt(const nsjail::MountPt& mpt);
const std::string flagsToStr(unsigned long flags);
bool isGenericMountOption(const std::string& opt);
void applyGenericMountOption(const std::string& opt, uintptr_t* flags);
bool resolveMountDestination(int root_fd, const std::string& dst, resolved_dst_t* resolved);
bool createMountTargetFd(
    int root_fd, const resolved_dst_t& resolved, bool is_dir, int* target_fd,
    const std::string& dst);
bool applyMountFlagsToMountFd(int mount_fd, uintptr_t flags, bool log_error = true);
const std::string procFdPath(int fd);
bool syncTestHook(const char* point);
bool captureMountIdentityFromFd(int fd, mount_t* mpt);
bool captureMountedDestinationIdentity(int root_fd, mount_t* mpt);
bool verifyMountDestinationVisible(int root_fd, const mount_t& mpt);

#if defined(NSJAIL_TEST_HOOKS)
#define NSJAIL_SYNC_TEST_HOOK(point_literal) ::mnt::syncTestHook(point_literal)
#define NSJAIL_SYNC_TEST_HOOK_SUFFIX(prefix_literal, suffix_expr)                                   \
	::mnt::syncTestHook((std::string(prefix_literal) + (suffix_expr)).c_str())
#else
#define NSJAIL_SYNC_TEST_HOOK(point_literal) true
#define NSJAIL_SYNC_TEST_HOOK_SUFFIX(prefix_literal, suffix_expr) true
#endif

}  // namespace mnt

#endif /* NS_MNT_H */
