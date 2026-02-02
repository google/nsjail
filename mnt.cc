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

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "mnt_legacy.h"
#include "mnt_newapi.h"
#include "subproc.h"
#include "util.h"

namespace mnt {

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
		if (log_errors) {
			PLOG_D("mkdir('%s')", path.c_str());
		}
		return false;
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

	/* Remounting R/O, if needed. Only for mount points that were actually mounted */
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
