/*

   nsjail - mount namespace routines using the legacy mount(2) API
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

#include "mnt_legacy.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "mnt.h"
#include "util.h"

namespace mnt {
namespace legacy {
#if !defined(MS_LAZYTIME)
#define MS_LAZYTIME (1 << 25)
#endif
#if !defined(ST_NOSYMFOLLOW)
#define ST_NOSYMFOLLOW 8192
#endif

static bool isDirectory(const char* path) {
	if (!path) {
		return true;
	}
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
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

	if (proto.has_is_dir()) {
		mpt.is_dir = proto.is_dir();
	} else if (!proto.src_content().empty()) {
		mpt.is_dir = false;
	} else if (mpt.src.empty()) {
		mpt.is_dir = true;
	} else if (mpt.flags & MS_BIND) {
		mpt.is_dir = isDirectory(mpt.src.c_str());
	} else {
		mpt.is_dir = true;
	}

	return mpt;
}

static int tryMountRW(mount_t* mpt, const char* src, const char* dst) {
	int res = mount(src, dst, mpt->mpt->fstype().c_str(), mpt->flags & ~MS_RDONLY,
	    mpt->mpt->options().c_str());

	if (res == -1 && errno == EPERM && (mpt->flags & MS_RDONLY)) {
		LOG_W("mount('%s' -> '%s'): RW failed, falling back to RO", src, dst);
		res = mount(
		    src, dst, mpt->mpt->fstype().c_str(), mpt->flags, mpt->mpt->options().c_str());
	}
	return res;
}

static bool createMountTarget(const std::string& path, bool is_dir) {
	if (is_dir) {
		if (mkdir(path.c_str(), 0711) == -1 && errno != EEXIST) {
			PLOG_W("mkdir('%s')", path.c_str());
			return false;
		}
	} else {
		int fd =
		    TEMP_FAILURE_RETRY(open(path.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0644));
		if (fd == -1) {
			PLOG_W("open('%s', O_CREAT)", path.c_str());
			return false;
		}
		close(fd);
	}
	return true;
}

static bool mountSymlink(mount_t* mpt, const std::string& dstpath) {
	LOG_D("Creating symlink: %s -> %s", mpt->src.c_str(), dstpath.c_str());
	if (symlink(mpt->src.c_str(), dstpath.c_str()) == -1) {
		if (mpt->mpt->mandatory()) {
			PLOG_E("symlink('%s' -> '%s')", mpt->src.c_str(), dstpath.c_str());
			return false;
		}
		PLOG_W("symlink('%s' -> '%s') failed (non-mandatory)", mpt->src.c_str(),
		    dstpath.c_str());
	}
	return true;
}

static bool mountWithDynamicContent(
    mount_t* mpt, const std::string& dstpath, const std::string& tmpdir) {
	static uint64_t counter = 0;
	std::string srcpath = tmpdir + "/dynamic." + std::to_string(++counter);
	defer {
		unlink(srcpath.c_str());
	};

	int fd = TEMP_FAILURE_RETRY(
	    open(srcpath.c_str(), O_CREAT | O_EXCL | O_CLOEXEC | O_WRONLY, 0644));
	if (fd == -1) {
		PLOG_W("open('%s', O_CREAT)", srcpath.c_str());
		return false;
	}

	const auto& content = mpt->mpt->src_content();
	bool write_ok = util::writeToFd(fd, content.data(), content.length());
	close(fd);

	if (!write_ok) {
		LOG_W("Failed to write %zu bytes to '%s'", content.length(), srcpath.c_str());
		return false;
	}

	mpt->flags |= MS_BIND | MS_REC | MS_PRIVATE;
	if (tryMountRW(mpt, srcpath.c_str(), dstpath.c_str()) == -1) {
		PLOG_W("mount('%s' -> '%s')", srcpath.c_str(), dstpath.c_str());
		return false;
	}

	mpt->mounted = true;
	return true;
}

static bool mountSinglePoint(mount_t* mpt, const char* newroot, const char* tmpdir) {
	LOG_D("Mounting (legacy): %s", mnt::describeMountPt(*mpt->mpt).c_str());

	const std::string dstpath = std::string(newroot) + "/" + mpt->dst;
	std::string srcpath = mpt->src.empty() ? "none" : mpt->src;

	if (!util::createDirRecursively(dstpath.c_str())) {
		LOG_W("Failed to create parent directories for '%s'", dstpath.c_str());
		return false;
	}

	if (mpt->mpt->is_symlink()) {
		return mountSymlink(mpt, dstpath);
	}

	if (!createMountTarget(dstpath, mpt->is_dir)) {
		return false;
	}

	if (!mpt->mpt->src_content().empty()) {
		return mountWithDynamicContent(mpt, dstpath, tmpdir);
	}

	if (tryMountRW(mpt, srcpath.c_str(), dstpath.c_str()) == -1) {
		if (errno == EACCES) {
			PLOG_W("mount('%s' -> '%s'): try 'chmod o+x' on source path",
			    srcpath.c_str(), dstpath.c_str());
		} else if (mpt->mpt->fstype() == "proc") {
			PLOG_W("mount('%s' -> '%s'): procfs mount may fail if /proc has "
			       "overmounts (e.g., /dev/null on /proc/kcore)",
			    srcpath.c_str(), dstpath.c_str());
		} else {
			PLOG_W("mount('%s' -> '%s')", srcpath.c_str(), dstpath.c_str());
		}
		return false;
	}

	mpt->mounted = true;
	return true;
}

static unsigned long computeRemountFlags(const mount_t& mpt, const struct statvfs& vfs) {
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

bool remountPt(mnt::mount_t& mpt) {
	if (!mpt.mounted || mpt.mpt->is_symlink()) {
		return true;
	}

	struct statvfs vfs;
	if (TEMP_FAILURE_RETRY(statvfs(mpt.dst.c_str(), &vfs)) == -1) {
		PLOG_W("statvfs('%s')", mpt.dst.c_str());
		return false;
	}

	unsigned long flags = computeRemountFlags(mpt, vfs);
	LOG_D("Remounting '%s' with flags: %s", mpt.dst.c_str(), mnt::flagsToStr(flags).c_str());

	if (mount(mpt.dst.c_str(), mpt.dst.c_str(), nullptr, flags, nullptr) == -1) {
		PLOG_W("mount('%s', flags=%s)", mpt.dst.c_str(), mnt::flagsToStr(flags).c_str());
		return false;
	}
	return true;
}

std::unique_ptr<std::string> buildMountTree(nsj_t* nsj, std::vector<mnt::mount_t>* mounted_mpts) {
	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return nullptr;
	}

	const size_t tmpfsSize = 16 * 1024 * 1024;

	auto destdir = mnt::findWorkDir(nsj, "root");
	if (!destdir) {
		return nullptr;
	}

	if (mount("/", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1) {
		PLOG_E("mount('/', MS_REC|MS_PRIVATE)");
		return nullptr;
	}

	if (mount(nullptr, destdir->c_str(), "tmpfs", 0,
		("size=" + std::to_string(tmpfsSize)).c_str()) == -1) {
		PLOG_E("mount('%s', tmpfs)", destdir->c_str());
		return nullptr;
	}

	auto tmpdir = mnt::findWorkDir(nsj, "tmp");
	if (!tmpdir) {
		return nullptr;
	}

	if (mount(nullptr, tmpdir->c_str(), "tmpfs", 0,
		("size=" + std::to_string(tmpfsSize)).c_str()) == -1) {
		PLOG_E("mount('%s', tmpfs)", tmpdir->c_str());
		return nullptr;
	}

	for (const auto& proto : nsj->njc.mount()) {
		mount_t mpt = prepareMountPoint(proto);

		if (!mountSinglePoint(&mpt, destdir->c_str(), tmpdir->c_str())) {
			if (mpt.mpt->mandatory()) {
				LOG_E("Failed to mount mandatory point: %s", QC(mpt.dst));
				return nullptr;
			}
		}
		mounted_mpts->push_back(mpt);
	}

	if (!nsj->is_root_rw) {
		if (mount(destdir->c_str(), destdir->c_str(), nullptr, MS_REMOUNT | MS_RDONLY,
			nullptr) == -1) {
			PLOG_E("mount('%s', MS_REMOUNT|MS_RDONLY)", destdir->c_str());
			return nullptr;
		}
	}

	if (umount2(tmpdir->c_str(), MNT_DETACH) == -1) {
		PLOG_E("umount2('%s', MNT_DETACH)", tmpdir->c_str());
		return nullptr;
	}

	return destdir;
}

}  // namespace legacy
}  // namespace mnt
