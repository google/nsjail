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

#include "mnt.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#endif
#if __has_include(<linux/stat.h>)
#include <linux/stat.h>
#endif
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <deque>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "mnt_legacy.h"
#include "mnt_newapi.h"
#include "subproc.h"
#include "util.h"

namespace mnt {

static bool readLinkAtToString(int dirfd, const std::string& name, std::string* target) {
	char buf[PATH_MAX + 1];
	ssize_t len = TEMP_FAILURE_RETRY(readlinkat(dirfd, name.c_str(), buf, sizeof(buf) - 1));
	if (len < 0) {
		PLOG_W("readlinkat(%d, '%s')", dirfd, name.c_str());
		return false;
	}
	buf[len] = '\0';
	target->assign(buf, len);
	return true;
}

static bool splitMountDestination(const std::string& dst, std::vector<std::string>* components) {
	components->clear();
	if (dst.find('\0') != std::string::npos) {
		LOG_W("Mount destination contains NUL byte");
		return false;
	}

	for (const auto& component : util::strSplit(dst, '/')) {
		if (component.empty() || component == ".") {
			continue;
		}
		if (component == "..") {
			LOG_W("Mount destination contains '..' component: %s", QC(dst));
			return false;
		}
		components->push_back(component);
	}
	return true;
}

static void prependPathComponents(const std::string& path, std::deque<std::string>* pending) {
	auto components = util::strSplit(path, '/');
	for (auto it = components.rbegin(); it != components.rend(); ++it) {
		pending->push_front(*it);
	}
}

const std::string procFdPath(int fd) {
	return util::StrPrintf("/proc/self/fd/%d", fd);
}

static bool openLiveMountPathFd(int root_fd, const std::string& dst, int* live_fd);

static int reopenDirFd(int dirfd) {
	return TEMP_FAILURE_RETRY(openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
}

static bool captureFdIdentity(int fd, mount_identity_t* identity) {
	*identity = {};

	struct stat st;
	if (fstat(fd, &st) == -1) {
		PLOG_W("fstat(fd=%d)", fd);
		return false;
	}

	identity->valid = true;
	identity->dev = st.st_dev;
	identity->ino = st.st_ino;
	identity->type = st.st_mode & S_IFMT;

#if defined(__NR_statx) && defined(AT_EMPTY_PATH) && defined(STATX_MNT_ID)
	struct statx stx = {};
	if (util::syscall(__NR_statx, (uintptr_t)fd, (uintptr_t)"",
		(uintptr_t)(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW),
		(uintptr_t)(STATX_TYPE | STATX_INO | STATX_MNT_ID), (uintptr_t)&stx) == 0) {
		identity->has_mount_id = true;
		identity->mnt_id = stx.stx_mnt_id;
		identity->ino = stx.stx_ino;
		identity->type = stx.stx_mode & S_IFMT;
		return true;
	}
	if (errno != ENOSYS && errno != EINVAL && errno != EPERM) {
		PLOG_W("statx(fd=%d, AT_EMPTY_PATH)", fd);
		return false;
	}
#endif

	return true;
}

static bool identitiesMatch(const mount_identity_t& expected, const mount_identity_t& actual) {
	if (!expected.valid || !actual.valid) {
		return false;
	}
	if (expected.type != actual.type) {
		return false;
	}
	if (expected.dev != actual.dev) {
		return false;
	}
	if (expected.ino != actual.ino) {
		return false;
	}
	if (expected.has_mount_id && actual.has_mount_id && expected.mnt_id != actual.mnt_id) {
		return false;
	}
	return true;
}

bool syncTestHook(const char* point) {
#if defined(NSJAIL_TEST_HOOKS)
	const char* hook_dir = getenv("NSJAIL_TEST_HOOK_DIR");
	if (hook_dir == nullptr || hook_dir[0] == '\0') {
		return true;
	}

	const std::string events_fifo = std::string(hook_dir) + "/events.fifo";
	const std::string control_fifo = std::string(hook_dir) + "/control.fifo";

	int events_fd = TEMP_FAILURE_RETRY(open(events_fifo.c_str(), O_WRONLY | O_CLOEXEC));
	if (events_fd < 0) {
		PLOG_W("open('%s', O_WRONLY)", events_fifo.c_str());
		return false;
	}

	const std::string event = std::string(point) + "\n";
	bool wrote = util::writeToFd(events_fd, event.data(), event.size());
	close(events_fd);
	if (!wrote) {
		LOG_W("Failed to publish test hook event '%s'", point);
		return false;
	}

	int control_fd = TEMP_FAILURE_RETRY(open(control_fifo.c_str(), O_RDONLY | O_CLOEXEC));
	if (control_fd < 0) {
		PLOG_W("open('%s', O_RDONLY)", control_fifo.c_str());
		return false;
	}

	char buf[64];
	ssize_t len = TEMP_FAILURE_RETRY(read(control_fd, buf, sizeof(buf) - 1));
	close(control_fd);
	if (len <= 0) {
		LOG_W("Failed to receive test hook acknowledgement for '%s'", point);
		return false;
	}
	buf[len] = '\0';
	if (strncmp(buf, "continue", 8) != 0) {
		LOG_W("Unexpected test hook acknowledgement for '%s': %s", point, buf);
		return false;
	}
	return true;
#else
	(void)point;
	return true;
#endif
}

bool resolveMountDestination(int root_fd, const std::string& dst, resolved_dst_t* resolved) {
	resolved->dirfd = -1;
	resolved->leaf.clear();
	resolved->is_root = false;

	std::vector<std::string> components;
	if (!splitMountDestination(dst, &components)) {
		return false;
	}

	if (components.empty()) {
		resolved->dirfd = reopenDirFd(root_fd);
		if (resolved->dirfd < 0) {
			PLOG_W("openat(root_fd, '.')");
			return false;
		}
		resolved->leaf = ".";
		resolved->is_root = true;
		return true;
	}

	resolved->leaf = components.back();
	components.pop_back();

	std::vector<int> dir_stack;
	dir_stack.push_back(dup(root_fd));
	if (dir_stack.back() < 0) {
		PLOG_W("dup(root_fd)");
		return false;
	}
	defer {
		for (int fd : dir_stack) {
			close(fd);
		}
	};

	std::deque<std::string> pending(components.begin(), components.end());
	size_t symlink_expansions = 0;

	while (!pending.empty()) {
		std::string component = pending.front();
		pending.pop_front();

		if (component.empty() || component == ".") {
			continue;
		}
		if (component == "..") {
			if (dir_stack.size() > 1) {
				close(dir_stack.back());
				dir_stack.pop_back();
			}
			continue;
		}

		int fd =
		    openat(dir_stack.back(), component.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			if (errno == ENOENT) {
				if (mkdirat(dir_stack.back(), component.c_str(), 0755) == -1 &&
				    errno != EEXIST) {
					if (errno != EROFS ||
					    !util::existsAsDirAtNoFollow(
						dir_stack.back(), component.c_str())) {
						PLOG_W("mkdirat(%d, '%s')", dir_stack.back(),
						    component.c_str());
						return false;
					}
				}

				fd = openat(dir_stack.back(), component.c_str(),
				    O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
				if (fd < 0) {
					PLOG_W("openat(%d, '%s', O_DIRECTORY|O_NOFOLLOW)",
					    dir_stack.back(), component.c_str());
					return false;
				}
				dir_stack.push_back(fd);
				continue;
			}

			PLOG_W("openat(%d, '%s', O_PATH|O_NOFOLLOW)", dir_stack.back(),
			    component.c_str());
			return false;
		}

		struct stat st;
		if (fstat(fd, &st) == -1) {
			PLOG_W("fstat(fd=%d)", fd);
			close(fd);
			return false;
		}

		if (S_ISLNK(st.st_mode)) {
			close(fd);
			if (++symlink_expansions > 40) {
				LOG_W("Mount destination exceeded symlink expansion limit: %s",
				    QC(dst));
				return false;
			}

			std::string target;
			if (!readLinkAtToString(dir_stack.back(), component, &target)) {
				return false;
			}
			if (!target.empty() && target[0] == '/') {
				while (dir_stack.size() > 1) {
					close(dir_stack.back());
					dir_stack.pop_back();
				}
			}
			prependPathComponents(target, &pending);
			continue;
		}

		if (!S_ISDIR(st.st_mode)) {
			LOG_W("Mount destination prefix is not a directory: %s/%s", QC(dst),
			    component.c_str());
			close(fd);
			return false;
		}

		dir_stack.push_back(fd);
	}

	resolved->dirfd = reopenDirFd(dir_stack.back());
	if (resolved->dirfd < 0) {
		PLOG_W("openat(dirfd, '.')");
		return false;
	}
	return true;
}

bool createMountTargetFd(int root_fd, const resolved_dst_t& resolved, bool is_dir, int* target_fd,
    const std::string& dst) {
	*target_fd = -1;

	if (resolved.is_root) {
		if (!is_dir) {
			LOG_W("Mount destination '%s' resolves to root but requires a file target",
			    QC(dst));
			return false;
		}
		*target_fd = dup(resolved.dirfd);
		if (*target_fd < 0) {
			PLOG_W("dup(dirfd)");
			return false;
		}
		return true;
	}

	struct stat leaf_st;
	if (fstatat(resolved.dirfd, resolved.leaf.c_str(), &leaf_st, AT_SYMLINK_NOFOLLOW) == 0) {
		if (!S_ISLNK(leaf_st.st_mode)) {
			goto create_or_open_leaf;
		}
		if (!openLiveMountPathFd(root_fd, dst, target_fd)) {
			LOG_W("Mount destination symlink '%s' did not resolve safely within root",
			    QC(dst));
			return false;
		}

		struct stat target_st;
		if (fstat(*target_fd, &target_st) == -1) {
			PLOG_W("fstat(target_fd=%d)", *target_fd);
			close(*target_fd);
			*target_fd = -1;
			return false;
		}
		if (is_dir != S_ISDIR(target_st.st_mode)) {
			LOG_W("Mount destination '%s' resolved to an unexpected object type",
			    QC(dst));
			close(*target_fd);
			*target_fd = -1;
			return false;
		}
		return true;
	}
	if (errno != ENOENT) {
		PLOG_W("fstatat(%d, '%s', AT_SYMLINK_NOFOLLOW)", resolved.dirfd, resolved.leaf.c_str());
		return false;
	}

create_or_open_leaf:
	if (is_dir) {
		if (mkdirat(resolved.dirfd, resolved.leaf.c_str(), 0711) == -1 && errno != EEXIST) {
			if (errno != EROFS ||
			    !util::existsAsDirAtNoFollow(resolved.dirfd, resolved.leaf.c_str())) {
				PLOG_W("mkdirat(%d, '%s')", resolved.dirfd, resolved.leaf.c_str());
				return false;
			}
		}
		*target_fd = TEMP_FAILURE_RETRY(openat(resolved.dirfd, resolved.leaf.c_str(),
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
		if (*target_fd < 0) {
			PLOG_W("openat(%d, '%s', O_DIRECTORY|O_NOFOLLOW)", resolved.dirfd,
			    resolved.leaf.c_str());
			return false;
		}
		return true;
	}

	*target_fd = TEMP_FAILURE_RETRY(openat(resolved.dirfd, resolved.leaf.c_str(),
	    O_CREAT | O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0644));
	if (*target_fd >= 0) {
		return true;
	}
	if (errno != EROFS || !util::existsAsRegAtNoFollow(resolved.dirfd, resolved.leaf.c_str())) {
		PLOG_W(
		    "openat(%d, '%s', O_CREAT|O_NOFOLLOW)", resolved.dirfd, resolved.leaf.c_str());
		return false;
	}

	*target_fd = TEMP_FAILURE_RETRY(
	    openat(resolved.dirfd, resolved.leaf.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
	if (*target_fd < 0) {
		PLOG_W(
		    "openat(%d, '%s', O_RDONLY|O_NOFOLLOW)", resolved.dirfd, resolved.leaf.c_str());
		return false;
	}
	return true;
}

bool applyMountFlagsToMountFd(int mount_fd, uintptr_t flags, bool log_error) {
#if defined(__NR_mount_setattr) && defined(AT_EMPTY_PATH) && defined(MOUNT_ATTR_RDONLY) &&         \
    defined(MOUNT_ATTR_NOSUID) && defined(MOUNT_ATTR_NODEV) && defined(MOUNT_ATTR_NOEXEC)
	struct mount_attr attr = {};

	if (flags & MS_RDONLY) {
		attr.attr_set |= MOUNT_ATTR_RDONLY;
	} else {
		attr.attr_clr |= MOUNT_ATTR_RDONLY;
	}
	if (flags & MS_NOSUID) {
		attr.attr_set |= MOUNT_ATTR_NOSUID;
	}
	if (flags & MS_NODEV) {
		attr.attr_set |= MOUNT_ATTR_NODEV;
	}
	if (flags & MS_NOEXEC) {
		attr.attr_set |= MOUNT_ATTR_NOEXEC;
	}
#if defined(MOUNT_ATTR_NOSYMFOLLOW)
	if (flags & MS_NOSYMFOLLOW) {
		attr.attr_set |= MOUNT_ATTR_NOSYMFOLLOW;
	}
#endif
#if defined(MOUNT_ATTR__ATIME) && defined(MOUNT_ATTR_NOATIME) && defined(MOUNT_ATTR_STRICTATIME)
	if (flags & (MS_NOATIME | MS_STRICTATIME | MS_RELATIME)) {
		attr.attr_clr |= MOUNT_ATTR__ATIME;
		if (flags & MS_NOATIME) {
			attr.attr_set |= MOUNT_ATTR_NOATIME;
		} else if (flags & MS_STRICTATIME) {
			attr.attr_set |= MOUNT_ATTR_STRICTATIME;
		} else {
			attr.attr_set |= MOUNT_ATTR_RELATIME;
		}
	}
#endif
#if defined(MOUNT_ATTR_NODIRATIME)
	if (flags & MS_NODIRATIME) {
		attr.attr_set |= MOUNT_ATTR_NODIRATIME;
	}
#endif

	if (util::syscall(__NR_mount_setattr, (uintptr_t)mount_fd, (uintptr_t)"",
		(uintptr_t)AT_EMPTY_PATH, (uintptr_t)&attr, sizeof(attr)) < 0) {
		if (log_error) {
			PLOG_W("mount_setattr(fd=%d, set=0x%" PRIx64 ", clr=0x%" PRIx64 ")",
			    mount_fd, (uint64_t)attr.attr_set, (uint64_t)attr.attr_clr);
		}
		return false;
	}
	return true;
#else
	errno = ENOSYS;
	if (log_error) {
		LOG_W("mount_setattr unavailable for remount handling");
	}
	return false;
#endif
}

bool isGenericMountOption(const std::string& opt) {
	return opt == "ro" || opt == "rw" || opt == "nosuid" || opt == "suid" || opt == "nodev" ||
	       opt == "dev" || opt == "noexec" || opt == "exec";
}

static bool openLiveMountPathFdFallback(int root_fd, const std::string& dst, int* live_fd) {
	*live_fd = -1;

	std::vector<std::string> components;
	if (!splitMountDestination(dst, &components)) {
		return false;
	}

	if (components.empty()) {
		*live_fd = dup(root_fd);
		if (*live_fd < 0) {
			PLOG_W("dup(root_fd)");
			return false;
		}
		return true;
	}

	std::vector<int> dir_stack;
	dir_stack.push_back(dup(root_fd));
	if (dir_stack.back() < 0) {
		PLOG_W("dup(root_fd)");
		return false;
	}
	defer {
		for (int fd : dir_stack) {
			close(fd);
		}
	};

	std::deque<std::string> pending(components.begin(), components.end());
	size_t symlink_expansions = 0;

	while (!pending.empty()) {
		std::string component = pending.front();
		pending.pop_front();
		const bool final = pending.empty();

		if (component.empty() || component == ".") {
			continue;
		}
		if (component == "..") {
			if (dir_stack.size() > 1) {
				close(dir_stack.back());
				dir_stack.pop_back();
			}
			continue;
		}

		int fd = TEMP_FAILURE_RETRY(
		    openat(dir_stack.back(), component.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW));
		if (fd < 0) {
			PLOG_W("openat(%d, '%s', O_PATH|O_NOFOLLOW)", dir_stack.back(),
			    component.c_str());
			return false;
		}

		struct stat st;
		if (fstat(fd, &st) == -1) {
			PLOG_W("fstat(fd=%d)", fd);
			close(fd);
			return false;
		}

		if (S_ISLNK(st.st_mode)) {
			close(fd);
			if (++symlink_expansions > 40) {
				LOG_W("Live mount destination exceeded symlink expansion limit: %s",
				    QC(dst));
				return false;
			}

			std::string target;
			if (!readLinkAtToString(dir_stack.back(), component, &target)) {
				return false;
			}
			if (!target.empty() && target[0] == '/') {
				while (dir_stack.size() > 1) {
					close(dir_stack.back());
					dir_stack.pop_back();
				}
			}
			prependPathComponents(target, &pending);
			continue;
		}

		if (final) {
			*live_fd = fd;
			return true;
		}

		if (!S_ISDIR(st.st_mode)) {
			LOG_W("Live mount destination prefix is not a directory: %s/%s", QC(dst),
			    component.c_str());
			close(fd);
			return false;
		}

		dir_stack.push_back(fd);
	}

	errno = ENOENT;
	LOG_W("Failed to resolve live mount destination: %s", QC(dst));
	return false;
}

static bool openLiveMountPathFd(int root_fd, const std::string& dst, int* live_fd) {
	*live_fd = -1;

	std::vector<std::string> components;
	if (!splitMountDestination(dst, &components)) {
		return false;
	}

	if (components.empty()) {
		*live_fd = dup(root_fd);
		if (*live_fd < 0) {
			PLOG_W("dup(root_fd)");
			return false;
		}
		return true;
	}

#if defined(__NR_openat2) && __has_include(<linux/openat2.h>)
	const char* rel_dst = util::stripLeadingSlashes(dst.c_str());
	struct open_how how = {
	    .flags = O_PATH | O_CLOEXEC,
	    .mode = 0,
	    .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	};
	*live_fd = util::syscall(__NR_openat2, (uintptr_t)root_fd,
	    (uintptr_t)(rel_dst[0] ? rel_dst : "."), (uintptr_t)&how, sizeof(how));
	if (*live_fd >= 0) {
		return true;
	}
	if (errno != ENOSYS) {
		PLOG_W("openat2(root_fd, '%s')", rel_dst);
		return false;
	}
#endif

	return openLiveMountPathFdFallback(root_fd, dst, live_fd);
}

bool captureMountedDestinationIdentity(int root_fd, mount_t* mpt) {
	mpt->identity = {};
	if (mpt->mpt->is_symlink() || mpt->dst == "/") {
		return true;
	}

	int live_fd = -1;
	if (!openLiveMountPathFd(root_fd, mpt->dst, &live_fd)) {
		LOG_W("Mounted destination '%s' could not be captured after attach", QC(mpt->dst));
		return false;
	}
	defer {
		close(live_fd);
	};

	if (!captureFdIdentity(live_fd, &mpt->identity)) {
		return false;
	}
	return true;
}

bool captureMountIdentityFromFd(int fd, mount_t* mpt) {
	mpt->identity = {};
	if (mpt->mpt->is_symlink() || mpt->dst == "/") {
		return true;
	}
	if (fd < 0) {
		errno = EBADF;
		PLOG_W("captureMountIdentityFromFd(fd=%d)", fd);
		return false;
	}
	return captureFdIdentity(fd, &mpt->identity);
}

bool verifyMountDestinationVisible(int root_fd, const mount_t& mpt) {
	if (!mpt.mounted || mpt.mpt->is_symlink() || mpt.dst == "/") {
		return true;
	}

	std::vector<std::string> components;
	if (!splitMountDestination(mpt.dst, &components)) {
		return false;
	}
	/*
	 * Only nested destinations can be stranded by a later prefix exchange.
	 * Top-level mount points do not have an in-root mutable prefix to retarget.
	 */
	if (components.size() < 2) {
		return true;
	}

	int live_fd = -1;
	if (!openLiveMountPathFd(root_fd, mpt.dst, &live_fd)) {
		LOG_W("Mounted destination '%s' no longer resolves via the configured path",
		    QC(mpt.dst));
		return false;
	}
	defer {
		close(live_fd);
	};

	struct stat st;
	if (fstat(live_fd, &st) == -1) {
		PLOG_W("fstat(live_fd=%d)", live_fd);
		return false;
	}
	if (mpt.is_dir != S_ISDIR(st.st_mode)) {
		LOG_W("Mounted destination '%s' resolved to an unexpected object type",
		    QC(mpt.dst));
		return false;
	}
	if (mpt.identity.valid) {
		mount_identity_t live_identity = {};
		if (!captureFdIdentity(live_fd, &live_identity)) {
			return false;
		}
		if (!identitiesMatch(mpt.identity, live_identity)) {
			LOG_W("Mounted destination '%s' no longer refers to the attached mount "
			      "(expected dev=%ju ino=%ju mnt_id=%ju, got dev=%ju ino=%ju mnt_id=%ju)",
			    QC(mpt.dst), (uintmax_t)mpt.identity.dev, (uintmax_t)mpt.identity.ino,
			    (uintmax_t)(mpt.identity.has_mount_id ? mpt.identity.mnt_id : 0),
			    (uintmax_t)live_identity.dev, (uintmax_t)live_identity.ino,
			    (uintmax_t)(live_identity.has_mount_id ? live_identity.mnt_id : 0));
			return false;
		}
	}
	return true;
}

void applyGenericMountOption(const std::string& opt, uintptr_t* flags) {
	if (opt == "ro") {
		*flags |= MS_RDONLY;
	} else if (opt == "rw") {
		*flags &= ~MS_RDONLY;
	} else if (opt == "nosuid") {
		*flags |= MS_NOSUID;
	} else if (opt == "suid") {
		*flags &= ~MS_NOSUID;
	} else if (opt == "nodev") {
		*flags |= MS_NODEV;
	} else if (opt == "dev") {
		*flags &= ~MS_NODEV;
	} else if (opt == "noexec") {
		*flags |= MS_NOEXEC;
	} else if (opt == "exec") {
		*flags &= ~MS_NOEXEC;
	}
}

const std::string flagsToStr(unsigned long flags) {
	std::string res;

	struct {
		uint32_t flag;
		const char* const name;
	} static const mountFlags[] = {
	    NS_VALSTR_STRUCT(MS_RDONLY),
	    NS_VALSTR_STRUCT(MS_NOSUID),
	    NS_VALSTR_STRUCT(MS_NODEV),
	    NS_VALSTR_STRUCT(MS_NOEXEC),
	    NS_VALSTR_STRUCT(MS_SYNCHRONOUS),
	    NS_VALSTR_STRUCT(MS_REMOUNT),
	    NS_VALSTR_STRUCT(MS_MANDLOCK),
	    NS_VALSTR_STRUCT(MS_DIRSYNC),
	    NS_VALSTR_STRUCT(MS_NOSYMFOLLOW),
	    NS_VALSTR_STRUCT(MS_NOATIME),
	    NS_VALSTR_STRUCT(MS_NODIRATIME),
	    NS_VALSTR_STRUCT(MS_BIND),
	    NS_VALSTR_STRUCT(MS_MOVE),
	    NS_VALSTR_STRUCT(MS_REC),
	    NS_VALSTR_STRUCT(MS_SILENT),
	    NS_VALSTR_STRUCT(MS_POSIXACL),
	    NS_VALSTR_STRUCT(MS_UNBINDABLE),
	    NS_VALSTR_STRUCT(MS_PRIVATE),
	    NS_VALSTR_STRUCT(MS_SLAVE),
	    NS_VALSTR_STRUCT(MS_SHARED),
	    NS_VALSTR_STRUCT(MS_RELATIME),
	    NS_VALSTR_STRUCT(MS_KERNMOUNT),
	    NS_VALSTR_STRUCT(MS_I_VERSION),
	    NS_VALSTR_STRUCT(MS_STRICTATIME),
	    NS_VALSTR_STRUCT(MS_LAZYTIME),
	    NS_VALSTR_STRUCT(MS_ACTIVE),
	    NS_VALSTR_STRUCT((uint32_t)MS_NOUSER),  // defined as (1<<31)
	};

	unsigned knownFlagMask = 0U;
	for (const auto& i : mountFlags) {
		if (flags & i.flag) {
			if (!res.empty()) {
				res.append("|");
			}
			res.append(i.name);
		}
		knownFlagMask |= i.flag;
	}

	if (flags & ~(knownFlagMask)) {
		util::StrAppend(&res, "|%#lx", flags & ~(knownFlagMask));
	}

	return res;
}

const std::string describeMountPt(const nsjail::MountPt& mpt) {
	std::string descr;

	descr.append(mpt.src().empty() ? "" : QC(mpt.src()))
	    .append(mpt.src().empty() ? "" : " -> ")
	    .append(QC(mpt.dst()))
	    .append(" type:")
	    .append(QC(mpt.fstype()))
	    .append(" options:")
	    .append(QC(mpt.options()));

	if (mpt.has_is_dir()) {
		descr.append(mpt.is_dir() ? " dir:true" : " dir:false");
	}
	if (!mpt.mandatory()) {
		descr.append(" mandatory:false");
	}
	if (!mpt.src_content().empty()) {
		descr.append(" src_content_len:")
		    .append(std::to_string(mpt.src_content().length()));
	}
	if (mpt.is_symlink()) {
		descr.append(" symlink:true");
	}

	return descr;
}

namespace fs = std::filesystem;

static bool tryCreateDir(const std::string& path, bool log_errors = true) {
	if (mkdir(path.c_str(), 0755) == -1 && errno != EEXIST) {
		if (errno != EROFS || !util::existsAsDir(path.c_str())) {
			if (log_errors) {
				PLOG_D("mkdir('%s')", path.c_str());
			}
			return false;
		}
	}
	if (access(path.c_str(), R_OK) == -1) {
		if (log_errors) {
			PLOG_W("access('%s', R_OK)", path.c_str());
		}
		return false;
	}
	LOG_D("Created directory '%s'", path.c_str());
	return true;
}

static std::string findWritableDirUnderRoot() {
	std::error_code ec;
	for (const auto& entry : fs::directory_iterator("/", ec)) {
		auto name = entry.path().filename().string();
		if (name == "." || name == "..") {
			continue;
		}
		if (!entry.is_directory(ec)) {
			continue;
		}
		if (access(entry.path().c_str(), W_OK | X_OK) == 0) {
			return entry.path().string();
		}
	}
	return "";
}

std::unique_ptr<std::string> findWorkDir(nsj_t* nsj, const char* purpose) {
	const std::string uid = std::to_string(nsj->orig_uid);
	const std::string suffix = "nsjail." + uid + "." + purpose;

	/* Try standard locations */
	std::vector<std::string> candidates = {
	    "/run/user/" + uid + "/nsjail/" + purpose,
	    "/run/user/" + suffix,
	    "/tmp/" + suffix,
	    "/dev/shm/" + suffix,
	};

	if (const char* tmpdir = getenv("TMPDIR")) {
		candidates.insert(candidates.begin() + 3, std::string(tmpdir) + "/" + suffix);
	}

	for (const auto& path : candidates) {
		size_t last_slash = path.rfind('/');
		if (last_slash != std::string::npos && last_slash > 0) {
			tryCreateDir(path.substr(0, last_slash), false);
		}
		if (tryCreateDir(path, true)) {
			return std::make_unique<std::string>(path);
		}
	}

	std::string root_dir = findWritableDirUnderRoot();
	if (!root_dir.empty()) {
		std::string candidate = root_dir + "/" + suffix;
		if (tryCreateDir(candidate, false)) {
			return std::make_unique<std::string>(candidate);
		}
	}

	std::string fallback = "/tmp/" + suffix + "." + std::to_string(util::rnd64());
	if (tryCreateDir(fallback, true)) {
		return std::make_unique<std::string>(fallback);
	}

	LOG_E("Failed to create work directory for '%s'", purpose);
	return nullptr;
}

static bool initNoCloneNs(nsj_t* nsj) {
	/*
	 * If CLONE_NEWNS is not used, we would be changing the global mount namespace, so simply
	 * use --chroot in this case
	 */
	if (nsj->chroot.empty()) {
		return true;
	}
	if (chroot(nsj->chroot.c_str()) == -1) {
		PLOG_E("chroot(%s)", QC(nsj->chroot));
		return false;
	}
	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return false;
	}
	return true;
}

static bool initCloneNs(nsj_t* nsj) {
	std::vector<mount_t> mounted_mpts;
	defer {
		for (auto& p : mounted_mpts) {
			if (p.fd >= 0) {
				close(p.fd);
				p.fd = -1;
			}
		}
	};

	std::unique_ptr<std::string> destdir;

	if (nsj->mnt_newapi) {
		destdir = newapi::buildMountTree(nsj, &mounted_mpts);
	} else {
		destdir = legacy::buildMountTree(nsj, &mounted_mpts);
	}

	if (!destdir) {
		LOG_E("Failed to build mount tree");
		return false;
	}

	/*
	 * Apply final mount attributes before pivot_root()/MS_MOVE. The target descriptors
	 * are captured while the mount tree is being constructed, and remounting them before
	 * relocating the root avoids relying on how moved mounts interact with later
	 * mount_setattr(AT_EMPTY_PATH) calls.
	 */
	for (auto& mpt : mounted_mpts) {
		bool success;
		if (nsj->mnt_newapi) {
			success = newapi::remountPt(mpt);
		} else {
			success = legacy::remountPt(mpt);
		}
		if (!success && mpt.mpt->mandatory()) {
			return false;
		}
	}

	if (!NSJAIL_SYNC_TEST_HOOK("mnt.before_visibility_check")) {
		return false;
	}

	int root_fd = openat(AT_FDCWD, destdir->c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root_fd < 0) {
		PLOG_E("openat('%s') before visibility verification", destdir->c_str());
		return false;
	}
	defer {
		close(root_fd);
	};

	for (const auto& mpt : mounted_mpts) {
		if (!verifyMountDestinationVisible(root_fd, mpt) && mpt.mpt->mandatory()) {
			return false;
		}
	}

	if (!nsj->njc.no_pivotroot()) {
		/*
		 * This requires some explanation: It's actually possible to pivot_root('/', '/').
		 * After this operation has been completed, the old root is mounted over the new
		 * root, and it's OK to simply umount('/') now, and to have new_root as '/'. This
		 * allows us not care about providing any special directory for old_root, which is
		 * sometimes not easy, given that e.g. /tmp might not always be present inside
		 * new_root
		 */
		if (util::syscall(__NR_pivot_root, (uintptr_t)destdir->c_str(),
			(uintptr_t)destdir->c_str()) == -1) {
			PLOG_E("pivot_root(%s, %s)", QC(*destdir), QC(*destdir));
			return false;
		}

		if (umount2("/", MNT_DETACH) == -1) {
			PLOG_E("umount2('/', MNT_DETACH)");
			return false;
		}

	} else {
		/*
		 * pivot_root would normally un-mount the old root, however in certain cases this
		 * operation is forbidden. There are systems (mainly embedded) that keep their root
		 * file system in RAM, when initially loaded by the kernel (e.g. initramfs),
		 * and there is no other file system that is mounted on top of it.In such systems,
		 * there is no option to pivot_root!
		 * For more information, see
		 * kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt. switch_root
		 * alternative: Innstead of un-mounting the old rootfs, it is over mounted by moving
		 * the new root to it.
		 */

		/* NOTE: Using mount move and chroot allows escaping back into the old root when
		 * proper capabilities are kept in the user namespace. It can be acheived by
		 * unmounting the new root and using setns to re-enter the mount namespace.
		 */
		LOG_W("Using no_pivotroot is escapable when user posseses relevant capabilities, "
		      "Use it with care!");

		if (chdir(destdir->c_str()) == -1) {
			PLOG_E("chdir(%s)", QC(*destdir));
			return false;
		}

		/* mount moving the new root on top of '/'. This operation is atomic and doesn't
		 *  involve un-mounting '/' at any stage
		 */
		if (mount(".", "/", NULL, MS_MOVE, NULL) == -1) {
			PLOG_E("mount('/', %s, NULL, MS_MOVE, NULL)", QC(*destdir));
			return false;
		}

		if (chroot(".") == -1) {
			PLOG_E("chroot(%s)", QC(*destdir));
			return false;
		}
	}

	return true;
}

static bool initNsInternal(nsj_t* nsj) {
	if (nsj->njc.clone_newns()) {
		if (!initCloneNs(nsj)) {
			return false;
		}
	} else {
		if (!initNoCloneNs(nsj)) {
			return false;
		}
	}

	if (chdir(nsj->njc.cwd().c_str()) == -1) {
		PLOG_E("chdir(%s)", QC(nsj->njc.cwd()));
		return false;
	}
	return true;
}

/*
 * With mode MODE_STANDALONE_EXECVE it's required to mount /proc inside a new process,
 * as the current process is still in the original PID namespace (man pid_namespaces)
 */
bool initNs(nsj_t* nsj) {
	if (nsj->njc.mode() != nsjail::Mode::EXECVE) {
		return initNsInternal(nsj);
	}

	pid_t pid = subproc::cloneProc(CLONE_FS, SIGCHLD);
	if (pid == -1) {
		return false;
	}

	if (pid == 0) {
		exit(initNsInternal(nsj) ? 0 : 0xff);
	}

	int status;
	while (wait4(pid, &status, 0, NULL) != pid);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return true;
	}
	return false;
}

}  // namespace mnt
