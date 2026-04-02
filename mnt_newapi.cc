/*
|
|   nsjail - mount namespace routines using the new mount API (fsopen/fsmount/move_mount)
|   -----------------------------------------
|
|   Copyright 2025 Google Inc. All Rights Reserved.
|
|   Licensed under the Apache License, Version 2.0 (the "License");
|   you may not use this file except in compliance with the License.
|   You may obtain a copy of the License at
|
|     http://www.apache.org/licenses/LICENSE-2.0
|
|   Unless required by applicable law or agreed to in writing, software
|   distributed under the License is distributed on an "AS IS" BASIS,
|   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
|   See the License for the specific language governing permissions and
|   limitations under the License.
|
*/

#include "mnt_newapi.h"

#include <fcntl.h>
// clang-format off
/* https://github.com/google/nsjail/issues/250 */
#include <sys/mount.h>
// clang-format on
#include <linux/mount.h>
#include <sys/syscall.h>

#include "logs.h"
#include "util.h"

/*
 * Compile-time feature detection for the new mount API.
 * Requires kernel headers with fsopen/fsconfig/fsmount/move_mount support.
 */
#if defined(__NR_fsopen) && defined(__NR_fsconfig) && defined(__NR_fsmount) &&                     \
    defined(__NR_move_mount) && defined(__NR_open_tree) && defined(__NR_mount_setattr) &&          \
    defined(FSOPEN_CLOEXEC) && defined(FSMOUNT_CLOEXEC) && defined(MOVE_MOUNT_F_EMPTY_PATH) &&     \
    defined(MOUNT_ATTR_RDONLY) && defined(MOUNT_ATTR_NOSUID) && defined(MOUNT_ATTR_NODEV) &&       \
    defined(MOUNT_ATTR_NOEXEC) && defined(AT_EMPTY_PATH) && defined(AT_RECURSIVE)
#define MNT_NEWAPI_SUPPORTED 1
#endif

#if !defined(MNT_NEWAPI_SUPPORTED)

namespace mnt {
namespace newapi {

bool isAvailable() {
	LOG_W("New mount API unavailable: missing compile-time support");
	return false;
}

bool remountPt(mnt::mount_t&) {
	return false;
}

std::unique_ptr<std::string> buildMountTree(nsj_t*, std::vector<mnt::mount_t>*) {
	return nullptr;
}

}  // namespace newapi
}  // namespace mnt

#else /* MNT_NEWAPI_SUPPORTED */

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

#include "macros.h"
#include "mnt.h"

namespace mnt {
namespace newapi {

static bool applyMountFlags(int fd, uintptr_t flags, bool log_error = true) {
	struct mount_attr attr = {};

	if (flags & MS_RDONLY) {
		attr.attr_set |= MOUNT_ATTR_RDONLY;
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

	if (util::syscall(__NR_mount_setattr, (uintptr_t)fd, (uintptr_t)"",
		(uintptr_t)AT_EMPTY_PATH, (uintptr_t)&attr, sizeof(attr)) < 0) {
		if (log_error) {
			PLOG_W("mount_setattr(fd=%d, flags=0x%" PRIx64 ")", fd,
			    (uint64_t)attr.attr_set);
		}
		return false;
	}
	return true;
}

static bool isGenericMountOption(const std::string& opt) {
	return opt == "ro" || opt == "rw" || opt == "nosuid" || opt == "suid" || opt == "nodev" ||
	       opt == "dev" || opt == "noexec" || opt == "exec";
}

static void applyGenericMountOption(const std::string& opt, uintptr_t* flags) {
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

static unsigned long computeLegacyRemountFlags(const mount_t& mpt, const struct statvfs& vfs) {
	struct {
		const unsigned long mount_flag;
		const unsigned long vfs_flag;
	} static const mountPairs[] = {
	    {MS_NOSUID, ST_NOSUID},
	    {MS_NODEV, ST_NODEV},
	    {MS_NOEXEC, ST_NOEXEC},
	    {MS_SYNCHRONOUS, ST_SYNCHRONOUS},
	    {MS_MANDLOCK, ST_MANDLOCK},
	    {MS_NOATIME, ST_NOATIME},
	    {MS_NODIRATIME, ST_NODIRATIME},
	    {MS_RELATIME, ST_RELATIME},
	    {MS_NOSYMFOLLOW, ST_NOSYMFOLLOW},
	};

	const unsigned long per_mountpoint_flags =
	    MS_LAZYTIME | MS_MANDLOCK | MS_NOATIME | MS_NODEV | MS_NODIRATIME | MS_NOEXEC |
	    MS_NOSUID | MS_RELATIME | MS_RDONLY | MS_SYNCHRONOUS | MS_NOSYMFOLLOW;

	unsigned long flags = MS_REMOUNT | MS_BIND | (mpt.flags & per_mountpoint_flags);
	for (const auto& i : mountPairs) {
		if (vfs.f_flag & i.vfs_flag) {
			flags |= i.mount_flag;
		}
	}
	return flags;
}

static bool remountWithLegacyMount(const mount_t& mpt) {
	struct statvfs vfs;
	if (TEMP_FAILURE_RETRY(statvfs(mpt.dst.c_str(), &vfs)) == -1) {
		PLOG_W("statvfs('%s')", mpt.dst.c_str());
		return false;
	}

	unsigned long flags = computeLegacyRemountFlags(mpt, vfs);
	LOG_D("Falling back to legacy remount for '%s' with flags: %s", mpt.dst.c_str(),
	    mnt::flagsToStr(flags).c_str());

	if (mount(mpt.dst.c_str(), mpt.dst.c_str(), nullptr, flags, nullptr) == -1) {
		PLOG_W("mount('%s', flags=%s)", mpt.dst.c_str(), mnt::flagsToStr(flags).c_str());
		return false;
	}
	return true;
}

static bool openMountForRemount(mount_t* mpt, int root_fd, const char* rel_dst) {
	mpt->fd = util::syscall(
	    __NR_open_tree, (uintptr_t)root_fd, (uintptr_t)rel_dst, (uintptr_t)OPEN_TREE_CLOEXEC);
	if (mpt->fd < 0) {
		PLOG_W("open_tree(root_fd, '%s')", rel_dst);
		return false;
	}
	mpt->mounted = true;
	return true;
}

static bool createDirAt(int dir_fd, const char* path, mode_t mode) {
	path = util::stripLeadingSlashes(path);
	if (!path[0]) {
		return true;
	}

	std::string cumulative;
	for (const auto& component : util::strSplit(path, '/')) {
		if (component.empty()) {
			continue;
		}

		if (!cumulative.empty()) {
			cumulative += '/';
		}
		cumulative += component;

		if (mkdirat(dir_fd, cumulative.c_str(), mode) == -1 && errno != EEXIST) {
			if (errno != EROFS || !util::existsAsDirAt(dir_fd, cumulative.c_str())) {
				PLOG_W("mkdirat(%d, '%s')", dir_fd, cumulative.c_str());
				return false;
			}
		}
	}
	return true;
}

static int createDetachedTmpfs(size_t size) {
	int fs_fd = util::syscall(__NR_fsopen, (uintptr_t)"tmpfs", (uintptr_t)FSOPEN_CLOEXEC);
	if (fs_fd < 0) {
		PLOG_W("fsopen('tmpfs')");
		return -1;
	}
	defer {
		close(fs_fd);
	};

	const std::string size_str = std::to_string(size);
	if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd, (uintptr_t)FSCONFIG_SET_STRING,
		(uintptr_t)"size", (uintptr_t)size_str.c_str(), (uintptr_t)0) < 0) {
		PLOG_W("fsconfig(size=%s)", size_str.c_str());
		return -1;
	}

	if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd, (uintptr_t)FSCONFIG_CMD_CREATE,
		(uintptr_t)nullptr, (uintptr_t)nullptr, (uintptr_t)0) < 0) {
		PLOG_W("fsconfig(CMD_CREATE)");
		return -1;
	}

	int mnt_fd =
	    util::syscall(__NR_fsmount, (uintptr_t)fs_fd, (uintptr_t)FSMOUNT_CLOEXEC, (uintptr_t)0);
	if (mnt_fd < 0) {
		PLOG_W("fsmount('tmpfs')");
	}
	return mnt_fd;
}

static int createFilesystemMount(const mount_t& mpt) {
	int fs_fd = util::syscall(
	    __NR_fsopen, (uintptr_t)mpt.mpt->fstype().c_str(), (uintptr_t)FSOPEN_CLOEXEC);
	if (fs_fd < 0) {
		PLOG_W("fsopen('%s')", mpt.mpt->fstype().c_str());
		return -1;
	}
	defer {
		close(fs_fd);
	};

	if (!mpt.src.empty() && mpt.src != "none") {
		if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd, (uintptr_t)FSCONFIG_SET_STRING,
			(uintptr_t)"source", (uintptr_t)mpt.src.c_str(), (uintptr_t)0) < 0) {
			PLOG_W("fsconfig(source='%s')", mpt.src.c_str());
			return -1;
		}
	}

	if (mpt.mpt->has_options()) {
		for (const auto& opt : util::strSplit(mpt.mpt->options(), ',')) {
			if (opt.empty() || isGenericMountOption(opt)) {
				continue;
			}
			auto eq = opt.find('=');
			if (eq != std::string::npos) {
				std::string key = opt.substr(0, eq);
				std::string val = opt.substr(eq + 1);
				if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd,
					(uintptr_t)FSCONFIG_SET_STRING, (uintptr_t)key.c_str(),
					(uintptr_t)val.c_str(), (uintptr_t)0) < 0) {
					PLOG_W("fsconfig(key='%s', value='%s')", key.c_str(),
					    val.c_str());
					return -1;
				}
			} else {
				if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd,
					(uintptr_t)FSCONFIG_SET_FLAG, (uintptr_t)opt.c_str(),
					(uintptr_t)nullptr, (uintptr_t)0) < 0) {
					PLOG_W("fsconfig(flag='%s')", opt.c_str());
					return -1;
				}
			}
		}
	}

	if (util::syscall(__NR_fsconfig, (uintptr_t)fs_fd, (uintptr_t)FSCONFIG_CMD_CREATE,
		(uintptr_t)nullptr, (uintptr_t)nullptr, (uintptr_t)0) < 0) {
		PLOG_W("fsconfig(CMD_CREATE)");
		return -1;
	}

	int mnt_fd =
	    util::syscall(__NR_fsmount, (uintptr_t)fs_fd, (uintptr_t)FSMOUNT_CLOEXEC, (uintptr_t)0);
	if (mnt_fd < 0) {
		PLOG_W("fsmount('%s')", mpt.mpt->fstype().c_str());
	}
	return mnt_fd;
}

static bool mountSymlinkAt(mount_t* mpt, int root_fd, const char* rel_dst) {
	LOG_D("Creating symlink: %s -> %s (fd-relative)", mpt->src.c_str(), rel_dst);
	if (symlinkat(mpt->src.c_str(), root_fd, rel_dst) == -1) {
		if (mpt->mpt->mandatory()) {
			PLOG_E("symlinkat('%s' -> '%s')", mpt->src.c_str(), rel_dst);
			return false;
		}
		PLOG_W("symlinkat('%s' -> '%s') failed (non-mandatory)", mpt->src.c_str(), rel_dst);
	}
	return true;
}

static bool mountDynamicContentAt(mount_t* mpt, int root_fd, const char* rel_dst) {
	static uint64_t counter = 0;
	std::string src_rel = ".dyn." + std::to_string(++counter);

	int src_fd =
	    openat(root_fd, src_rel.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
	if (src_fd < 0) {
		PLOG_W("openat(root_fd, '%s', O_CREAT)", src_rel.c_str());
		return false;
	}

	const auto& content = mpt->mpt->src_content();
	bool ok = util::writeToFd(src_fd, content.data(), content.length());
	close(src_fd);
	if (!ok) {
		LOG_W("Failed to write %zu bytes for dynamic content '%s'", content.length(),
		    rel_dst);
		unlinkat(root_fd, src_rel.c_str(), 0);
		return false;
	}

	int mnt_fd =
	    syscall(__NR_open_tree, root_fd, src_rel.c_str(), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (mnt_fd < 0) {
		PLOG_W("open_tree('%s')", src_rel.c_str());
		unlinkat(root_fd, src_rel.c_str(), 0);
		return false;
	}

	if (!applyMountFlags(mnt_fd, mpt->flags & ~MS_RDONLY)) {
		LOG_W("Failed to apply mount flags to '%s'", rel_dst);
	}

	if (util::syscall(__NR_move_mount, (uintptr_t)mnt_fd, (uintptr_t)"", (uintptr_t)root_fd,
		(uintptr_t)rel_dst, (uintptr_t)MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		PLOG_W("move_mount('%s' -> '%s')", src_rel.c_str(), rel_dst);
		close(mnt_fd);
		unlinkat(root_fd, src_rel.c_str(), 0);
		return false;
	}
	close(mnt_fd);

	if (unlinkat(root_fd, src_rel.c_str(), 0) == -1) {
		PLOG_W("unlinkat(root_fd, '%s')", src_rel.c_str());
	}

	mpt->fd = syscall(__NR_open_tree, root_fd, rel_dst, (unsigned int)OPEN_TREE_CLOEXEC);
	if (mpt->fd < 0) {
		PLOG_W("open_tree(root_fd, '%s')", rel_dst);
		return false;
	}
	mpt->mounted = true;
	return true;
}

static bool doBindMountAt(mount_t* mpt, int root_fd, const char* rel_dst) {
	unsigned int flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
	if (mpt->flags & MS_REC) {
		flags |= AT_RECURSIVE;
	}

	LOG_D("open_tree('%s', flags=0x%x)", mpt->src.c_str(), flags);
	int mnt_fd = syscall(__NR_open_tree, AT_FDCWD, mpt->src.c_str(), flags);
	if (mnt_fd < 0) {
		PLOG_W("open_tree('%s')", mpt->src.c_str());
		return false;
	}

	/* Apply non-RO flags now; RO applied later via remount */
	if (!applyMountFlags(mnt_fd, mpt->flags & ~MS_RDONLY)) {
		LOG_W("Failed to apply mount flags to '%s'", rel_dst);
	}

	if (util::syscall(__NR_move_mount, (uintptr_t)mnt_fd, (uintptr_t)"", (uintptr_t)root_fd,
		(uintptr_t)rel_dst, (uintptr_t)MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		PLOG_W("move_mount('%s' -> '%s')", mpt->src.c_str(), rel_dst);
		close(mnt_fd);
		return false;
	}
	close(mnt_fd);

	return openMountForRemount(mpt, root_fd, rel_dst);
}

static bool mountSinglePointAt(mount_t* mpt, int root_fd) {
	LOG_D("Mounting (new API): %s", mnt::describeMountPt(*mpt->mpt).c_str());

	const char* rel_dst = util::stripLeadingSlashes(mpt->dst.c_str());
	if (!rel_dst[0]) {
		rel_dst = ".";
	}

	const char* last_slash = strrchr(rel_dst, '/');
	if (last_slash && last_slash != rel_dst) {
		std::string parent(rel_dst, last_slash - rel_dst);
		if (!createDirAt(root_fd, parent.c_str(), 0755)) {
			LOG_W("Failed to create parent directories for '%s'", rel_dst);
			return false;
		}
	}

	if (mpt->mpt->is_symlink()) {
		return mountSymlinkAt(mpt, root_fd, rel_dst);
	}

	if (mpt->is_dir) {
		if (strcmp(rel_dst, ".") != 0 && mkdirat(root_fd, rel_dst, 0711) == -1 &&
		    errno != EEXIST) {
			if (errno != EROFS || !util::existsAsDirAt(root_fd, rel_dst)) {
				PLOG_W("mkdirat(root_fd, '%s')", rel_dst);
			}
		}
	} else {
		int fd = openat(root_fd, rel_dst, O_CREAT | O_RDONLY | O_CLOEXEC, 0644);
		if (fd >= 0) {
			close(fd);
		} else if (errno != EROFS || !util::existsAsRegAt(root_fd, rel_dst)) {
			PLOG_W("openat(root_fd, '%s', O_CREAT)", rel_dst);
		}
	}

	if (!mpt->mpt->src_content().empty()) {
		return mountDynamicContentAt(mpt, root_fd, rel_dst);
	}

	if (mpt->flags & MS_BIND) {
		return doBindMountAt(mpt, root_fd, rel_dst);
	}

	int mnt_fd = createFilesystemMount(*mpt);
	if (mnt_fd < 0) {
		return false;
	}

	if (!applyMountFlags(mnt_fd, mpt->flags & ~MS_RDONLY)) {
		LOG_W("Failed to apply mount flags to '%s'", rel_dst);
	}

	if (util::syscall(__NR_move_mount, (uintptr_t)mnt_fd, (uintptr_t)"", (uintptr_t)root_fd,
		(uintptr_t)rel_dst, (uintptr_t)MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		PLOG_W("move_mount() for '%s'", rel_dst);
		close(mnt_fd);
		return false;
	}
	close(mnt_fd);

	return openMountForRemount(mpt, root_fd, rel_dst);
}

static mount_t prepareMountPoint(const nsjail::MountPt& proto) {
	mount_t mpt = {
	    .mpt = &proto,
	    .src = "",
	    .dst = "",
	    .flags = 0,
	    .is_dir = true,
	    .mounted = false,
	    .fd = -1,
	};

	if (!proto.prefix_src_env().empty()) {
		if (const char* env = getenv(proto.prefix_src_env().c_str())) {
			mpt.src = env;
		} else {
			LOG_W("Environment variable not set: %s", QC(proto.prefix_src_env()));
			return mpt;
		}
	}
	mpt.src += proto.src();

	if (!proto.prefix_dst_env().empty()) {
		if (const char* env = getenv(proto.prefix_dst_env().c_str())) {
			mpt.dst = env;
		} else {
			LOG_W("Environment variable not set: %s", QC(proto.prefix_dst_env()));
			return mpt;
		}
	}
	mpt.dst += proto.dst();

	mpt.flags = proto.rw() ? 0 : (uintptr_t)MS_RDONLY;
	if (proto.is_bind()) {
		mpt.flags |= MS_BIND | MS_REC | MS_PRIVATE;
	}
	if (proto.nosuid()) {
		mpt.flags |= MS_NOSUID;
	}
	if (proto.nodev()) {
		mpt.flags |= MS_NODEV;
	}
	if (proto.noexec()) {
		mpt.flags |= MS_NOEXEC;
	}
	if (proto.has_options()) {
		for (const auto& opt : util::strSplit(proto.options(), ',')) {
			applyGenericMountOption(opt, &mpt.flags);
		}
	}

	if (proto.has_is_dir()) {
		mpt.is_dir = proto.is_dir();
	} else if (!proto.src_content().empty()) {
		mpt.is_dir = false;
	} else if (mpt.src.empty()) {
		mpt.is_dir = true;
	} else if (mpt.flags & MS_BIND) {
		struct stat st;
		mpt.is_dir = (stat(mpt.src.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
	} else {
		mpt.is_dir = true;
	}

	return mpt;
}

bool isAvailable() {
	if (util::kernelVersionAtLeast(6, 3, 0)) {
		LOG_D("New mount API available (kernel >= 6.3)");
		return true;
	}
	LOG_W("New mount API unavailable (kernel < 6.3)");
	return false;
}

bool remountPt(mnt::mount_t& mpt) {
	if (!mpt.mounted || mpt.mpt->is_symlink() || mpt.fd < 0) {
		return true;
	}

	close(mpt.fd);
	mpt.fd = -1;

	if (!remountWithLegacyMount(mpt)) {
		LOG_W("Failed to apply final flags to '%s'", mpt.dst.c_str());
		return false;
	}
	return true;
}

std::unique_ptr<std::string> buildMountTree(nsj_t* nsj, std::vector<mnt::mount_t>* mounted_mpts) {
	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return nullptr;
	}

	/* Make root mount private recursively */
	if (mount("/", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1) {
		PLOG_E("mount('/', MS_REC|MS_PRIVATE)");
		return nullptr;
	}

	int root_mfd = createDetachedTmpfs(16 * 1024 * 1024);
	if (root_mfd < 0) {
		LOG_E("Failed to create root tmpfs");
		return nullptr;
	}
	LOG_D("Created detached root tmpfs (fd=%d)", root_mfd);

	if (!applyMountFlags(root_mfd, 0)) {
		LOG_W("mount_setattr(root_mfd, 0) failed");
	}

	auto destdir = mnt::findWorkDir(nsj, "root");
	if (!destdir) {
		close(root_mfd);
		return nullptr;
	}

	/*
	 * Attach the new root to the filesystem *before* populating it.
	 * Attempting to populate a detached mount tree via move_mount() can fail with EINVAL
	 * on some kernels (e.g. 6.12) if the target is not yet attached.
	 */
	if (util::syscall(__NR_move_mount, (uintptr_t)root_mfd, (uintptr_t)"", (uintptr_t)AT_FDCWD,
		(uintptr_t)destdir->c_str(), (uintptr_t)MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		PLOG_E("move_mount(root_mfd -> '%s')", destdir->c_str());
		close(root_mfd);
		return nullptr;
	}
	close(root_mfd);

	int root_fd =
	    openat(AT_FDCWD, destdir->c_str(), O_RDONLY | O_CLOEXEC | O_PATH | O_DIRECTORY);
	if (root_fd < 0) {
		PLOG_E("openat('%s')", destdir->c_str());
		return nullptr;
	}
	defer {
		close(root_fd);
	};

	/* Build entire mount tree using fd-relative operations */
	for (const auto& proto : nsj->njc.mount()) {
		mount_t mpt = prepareMountPoint(proto);

		if (!mountSinglePointAt(&mpt, root_fd)) {
			if (mpt.mpt->mandatory()) {
				LOG_E("Failed to mount mandatory point: %s", QC(mpt.dst));
				return nullptr;
			}
		}
		mounted_mpts->push_back(mpt);
	}

	if (!nsj->is_root_rw) {
		struct mount_attr ro_attr = {};
		ro_attr.attr_set = MOUNT_ATTR_RDONLY;
		if (util::syscall(__NR_mount_setattr, (uintptr_t)root_fd, (uintptr_t)"",
			(uintptr_t)(AT_EMPTY_PATH | AT_RECURSIVE), (uintptr_t)&ro_attr,
			sizeof(ro_attr)) < 0) {
			PLOG_E("mount_setattr(root_fd, MOUNT_ATTR_RDONLY)");
			return nullptr;
		}
	}

	return destdir;
}

}  // namespace newapi
}  // namespace mnt

#endif /* MNT_NEWAPI_SUPPORTED */
