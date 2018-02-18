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
#include <syscall.h>
#include <unistd.h>

#include <string>

#include "logs.h"
#include "macros.h"
#include "subproc.h"
#include "util.h"

namespace mnt {

#if !defined(MS_LAZYTIME)
#define MS_LAZYTIME (1 << 25)
#endif /* if !defined(MS_LAZYTIME) */

static const std::string flagsToStr(uintptr_t flags) {
	std::string res;

	static struct {
		const uintptr_t flag;
		const char* const name;
	} const mountFlags[] = {
	    NS_VALSTR_STRUCT(MS_RDONLY),
	    NS_VALSTR_STRUCT(MS_NOSUID),
	    NS_VALSTR_STRUCT(MS_NODEV),
	    NS_VALSTR_STRUCT(MS_NOEXEC),
	    NS_VALSTR_STRUCT(MS_SYNCHRONOUS),
	    NS_VALSTR_STRUCT(MS_REMOUNT),
	    NS_VALSTR_STRUCT(MS_MANDLOCK),
	    NS_VALSTR_STRUCT(MS_DIRSYNC),
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
	};

	uintptr_t knownFlagMask = 0U;
	for (size_t i = 0; i < ARR_SZ(mountFlags); i++) {
		if (flags & mountFlags[i].flag) {
			res.append(mountFlags[i].name);
			res.append("|");
		}
		knownFlagMask |= mountFlags[i].flag;
	}

	char flagstr[32];
	snprintf(flagstr, sizeof(flagstr), "%#tx", flags & ~(knownFlagMask));
	res.append(flagstr);

	return res;
}

static bool isDir(const char* path) {
	/*
	 *  If the source dir is NULL, we assume it's a dir (for /proc and tmpfs)
	 */
	if (path == NULL) {
		return true;
	}
	struct stat st;
	if (stat(path, &st) == -1) {
		PLOG_D("stat('%s')", path);
		return false;
	}
	if (S_ISDIR(st.st_mode)) {
		return true;
	}
	return false;
}

static bool mountPt(mount_t* mpt, const char* newroot, const char* tmpdir) {
	char dst[PATH_MAX];
	snprintf(dst, sizeof(dst), "%s/%s", newroot, mpt->dst.c_str());

	LOG_D("Mounting '%s'", describeMountPt(*mpt).c_str());

	char srcpath[PATH_MAX];
	if (!mpt->src.empty()) {
		snprintf(srcpath, sizeof(srcpath), "%s", mpt->src.c_str());
	} else {
		snprintf(srcpath, sizeof(srcpath), "none");
	}

	if (mpt->is_symlink) {
		if (!util::createDirRecursively(dst)) {
			LOG_W("Couldn't create upper directories for '%s'", dst);
			return false;
		}
	} else if (mpt->is_dir) {
		if (!util::createDirRecursively(dst)) {
			LOG_W("Couldn't create upper directories for '%s'", dst);
			return false;
		}
		if (mkdir(dst, 0711) == -1 && errno != EEXIST) {
			PLOG_W("mkdir('%s')", dst);
		}
	} else {
		if (!util::createDirRecursively(dst)) {
			LOG_W("Couldn't create upper directories for '%s'", dst);
			return false;
		}
		int fd = TEMP_FAILURE_RETRY(open(dst, O_CREAT | O_RDONLY | O_CLOEXEC, 0644));
		if (fd >= 0) {
			close(fd);
		} else {
			PLOG_W("open('%s', O_CREAT|O_RDONLY|O_CLOEXEC, 0644)", dst);
		}
	}

	if (mpt->is_symlink) {
		LOG_D("symlink('%s', '%s')", srcpath, dst);
		if (symlink(srcpath, dst) == -1) {
			if (mpt->is_mandatory) {
				PLOG_W("symlink('%s', '%s')", srcpath, dst);
				return false;
			} else {
				PLOG_W("symlink('%s', '%s'), but it's not mandatory, continuing",
				    srcpath, dst);
			}
		}
		return true;
	}

	if (!mpt->src_content.empty()) {
		static uint64_t df_counter = 0;
		snprintf(
		    srcpath, sizeof(srcpath), "%s/dynamic_file.%" PRIu64, tmpdir, ++df_counter);
		int fd = TEMP_FAILURE_RETRY(
		    open(srcpath, O_CREAT | O_EXCL | O_CLOEXEC | O_WRONLY, 0644));
		if (fd < 0) {
			PLOG_W("open(srcpath, O_CREAT|O_EXCL|O_CLOEXEC|O_WRONLY, 0644) failed");
			return false;
		}
		if (util::writeToFd(fd, mpt->src_content.data(), mpt->src_content.length()) ==
		    false) {
			LOG_W("Writting %zu bytes to '%s' failed", mpt->src_content.length(),
			    srcpath);
			close(fd);
			return false;
		}
		close(fd);
		mpt->flags |= (MS_BIND | MS_REC | MS_PRIVATE);
	}

	/*
	 * Initially mount it as RW, it will be remounted later on if needed
	 */
	unsigned long flags = mpt->flags & ~(MS_RDONLY);
	if (mount(srcpath, dst, mpt->fs_type.c_str(), flags, mpt->options.c_str()) == -1) {
		if (errno == EACCES) {
			PLOG_W(
			    "mount('%s') src:'%s' dst:'%s' failed. "
			    "Try fixing this problem by applying 'chmod o+x' to the '%s' "
			    "directory and its ancestors",
			    describeMountPt(*mpt).c_str(), srcpath, dst, srcpath);
		} else {
			PLOG_W("mount('%s') src:'%s' dst:'%s' failed",
			    describeMountPt(*mpt).c_str(), srcpath, dst);
			if (mpt->fs_type.compare("proc")) {
				PLOG_W(
				    "procfs can only be mounted if the original /proc doesn't have "
				    "any other file-systems mounted on top of it (e.g. /dev/null "
				    "on top of /proc/kcore)");
			}
		}
		return false;
	} else {
		mpt->mounted = true;
	}

	if (!mpt->src_content.empty() && unlink(srcpath) == -1) {
		PLOG_W("unlink('%s')", srcpath);
	}
	return true;
}

static bool remountRO(const mount_t& mpt) {
	if (!mpt.mounted) {
		return true;
	}
	if (mpt.is_symlink) {
		return true;
	}
	if ((mpt.flags & MS_RDONLY) == 0) {
		return true;
	}

	struct statvfs vfs;
	if (TEMP_FAILURE_RETRY(statvfs(mpt.dst.c_str(), &vfs)) == -1) {
		PLOG_W("statvfs('%s')", mpt.dst.c_str());
		return false;
	}

	static struct {
		const unsigned long mount_flag;
		const unsigned long vfs_flag;
	} const mountPairs[] = {
	    {MS_RDONLY, ST_RDONLY},
	    {MS_NOSUID, ST_NOSUID},
	    {MS_NODEV, ST_NODEV},
	    {MS_NOEXEC, ST_NOEXEC},
	    {MS_SYNCHRONOUS, ST_SYNCHRONOUS},
	    {MS_MANDLOCK, ST_MANDLOCK},
	    {MS_NOATIME, ST_NOATIME},
	    {MS_NODIRATIME, ST_NODIRATIME},
	    {MS_RELATIME, ST_RELATIME},
	};

	unsigned long new_flags = MS_REMOUNT | MS_RDONLY | MS_BIND;
	for (size_t i = 0; i < ARR_SZ(mountPairs); i++) {
		if (vfs.f_flag & mountPairs[i].vfs_flag) {
			new_flags |= mountPairs[i].mount_flag;
		}
	}

	LOG_D("Re-mounting R/O '%s' (flags:%s)", mpt.dst.c_str(), flagsToStr(new_flags).c_str());
	if (mount(mpt.dst.c_str(), mpt.dst.c_str(), NULL, new_flags, 0) == -1) {
		PLOG_W("mount('%s', flags:%s)", mpt.dst.c_str(), flagsToStr(new_flags).c_str());
		return false;
	}

	return true;
}

static bool mkdirAndTest(const char* dir) {
	if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
		PLOG_D("Couldn't create '%s' directory", dir);
		return false;
	}
	if (access(dir, R_OK) == -1) {
		PLOG_W("access('%s', R_OK)", dir);
		return false;
	}
	LOG_D("Created accessible directory in '%s'", dir);
	return true;
}

static bool getDir(nsjconf_t* nsjconf, char* dir, const char* name) {
	snprintf(dir, PATH_MAX, "/run/user/%u/nsjail.%s", nsjconf->orig_uid, name);
	if (mkdirAndTest(dir)) {
		return true;
	}
	snprintf(dir, PATH_MAX, "/tmp/nsjail.%s", name);
	if (mkdirAndTest(dir)) {
		return true;
	}
	const char* tmp = getenv("TMPDIR");
	if (tmp) {
		snprintf(dir, PATH_MAX, "%s/nsjail.%s", tmp, name);
		if (mkdirAndTest(dir)) {
			return true;
		}
	}
	snprintf(dir, PATH_MAX, "/dev/shm/nsjail.%s", name);
	if (mkdirAndTest(dir)) {
		return true;
	}
	snprintf(dir, PATH_MAX, "/tmp/nsjail.%s.%" PRIx64, name, util::rnd64());
	if (mkdirAndTest(dir)) {
		return true;
	}

	LOG_E("Couldn't create tmp directory of type '%s'", name);
	return false;
}

static bool initNsInternal(nsjconf_t* nsjconf) {
	/*
	 * If CLONE_NEWNS is not used, we would be changing the global mount namespace, so simply
	 * use --chroot in this case
	 */
	if (!nsjconf->clone_newns) {
		if (nsjconf->chroot.empty()) {
			PLOG_E(
			    "--chroot was not specified, and it's required when not using "
			    "CLONE_NEWNS");
			return false;
		}
		if (chroot(nsjconf->chroot.c_str()) == -1) {
			PLOG_E("chroot('%s')", nsjconf->chroot.c_str());
			return false;
		}
		if (chdir("/") == -1) {
			PLOG_E("chdir('/')");
			return false;
		}
		return true;
	}

	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return false;
	}

	char destdir[PATH_MAX];
	if (!getDir(nsjconf, destdir, "root")) {
		LOG_E("Couldn't obtain root mount directories");
		return false;
	}

	/* Make changes to / (recursively) private, to avoid changing the global mount ns */
	if (mount("/", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
		PLOG_E("mount('/', '/', NULL, MS_REC|MS_PRIVATE, NULL)");
		return false;
	}
	if (mount(NULL, destdir, "tmpfs", 0, "size=16777216") == -1) {
		PLOG_E("mount('%s', 'tmpfs')", destdir);
		return false;
	}

	char tmpdir[PATH_MAX];
	if (!getDir(nsjconf, tmpdir, "tmp")) {
		LOG_E("Couldn't obtain temporary mount directories");
		return false;
	}
	if (mount(NULL, tmpdir, "tmpfs", 0, "size=16777216") == -1) {
		PLOG_E("mount('%s', 'tmpfs')", tmpdir);
		return false;
	}

	for (auto& p : nsjconf->mountpts) {
		if (!mountPt(&p, destdir, tmpdir) && p.is_mandatory) {
			return false;
		}
	}

	if (umount2(tmpdir, MNT_DETACH) == -1) {
		PLOG_E("umount2('%s', MNT_DETACH)", tmpdir);
		return false;
	}
	/*
	 * This requires some explanation: It's actually possible to pivot_root('/', '/'). After
	 * this operation has been completed, the old root is mounted over the new root, and it's OK
	 * to simply umount('/') now, and to have new_root as '/'. This allows us not care about
	 * providing any special directory for old_root, which is sometimes not easy, given that
	 * e.g. /tmp might not always be present inside new_root
	 */
	if (syscall(__NR_pivot_root, destdir, destdir) == -1) {
		PLOG_E("pivot_root('%s', '%s')", destdir, destdir);
		return false;
	}

	if (umount2("/", MNT_DETACH) == -1) {
		PLOG_E("umount2('/', MNT_DETACH)");
		return false;
	}
	if (chdir(nsjconf->cwd.c_str()) == -1) {
		PLOG_E("chdir('%s')", nsjconf->cwd.c_str());
		return false;
	}

	for (const auto& p : nsjconf->mountpts) {
		if (!remountRO(p) && p.is_mandatory) {
			return false;
		}
	}

	return true;
}

/*
 * With mode MODE_STANDALONE_EXECVE it's required to mount /proc inside a new process,
 * as the current process is still in the original PID namespace (man pid_namespaces)
 */
bool initNs(nsjconf_t* nsjconf) {
	if (nsjconf->mode != MODE_STANDALONE_EXECVE) {
		return initNsInternal(nsjconf);
	}

	pid_t pid = subproc::cloneProc(CLONE_FS | SIGCHLD);
	if (pid == -1) {
		return false;
	}

	if (pid == 0) {
		exit(initNsInternal(nsjconf) ? 0 : 0xff);
	}

	int status;
	while (wait4(pid, &status, 0, NULL) != pid)
		;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return true;
	}
	return false;
}

static bool addMountPt(mount_t* mnt, const std::string& src, const std::string& dst,
    const std::string& fstype, const std::string& options, uintptr_t flags, isDir_t is_dir,
    bool is_mandatory, const std::string& src_env, const std::string& dst_env,
    const std::string& src_content, bool is_symlink) {
	if (!src_env.empty()) {
		const char* e = getenv(src_env.c_str());
		if (e == NULL) {
			LOG_W("No such envvar:'%s'", src_env.c_str());
			return false;
		}
		mnt->src = e;
	}
	mnt->src.append(src);

	if (!dst_env.empty()) {
		const char* e = getenv(dst_env.c_str());
		if (e == NULL) {
			LOG_W("No such envvar:'%s'", dst_env.c_str());
			return false;
		}
		mnt->dst = e;
	}
	mnt->dst.append(dst);

	mnt->fs_type = fstype;
	mnt->options = options;
	mnt->flags = flags;
	mnt->is_symlink = is_symlink;
	mnt->is_mandatory = is_mandatory;
	mnt->mounted = false;
	mnt->src_content = src_content;

	switch (is_dir) {
	case NS_DIR_YES:
		mnt->is_dir = true;
		break;
	case NS_DIR_NO:
		mnt->is_dir = false;
		break;
	case NS_DIR_MAYBE: {
		if (!src_content.empty()) {
			mnt->is_dir = false;
		} else if (mnt->src.empty()) {
			mnt->is_dir = true;
		} else if (mnt->flags & MS_BIND) {
			mnt->is_dir = mnt::isDir(mnt->src.c_str());
		} else {
			mnt->is_dir = true;
		}
	} break;
	default:
		LOG_E("Unknown is_dir value: %d", is_dir);
		return false;
	}

	return true;
}

bool addMountPtHead(nsjconf_t* nsjconf, const std::string& src, const std::string& dst,
    const std::string& fstype, const std::string& options, uintptr_t flags, isDir_t is_dir,
    bool is_mandatory, const std::string& src_env, const std::string& dst_env,
    const std::string& src_content, bool is_symlink) {
	mount_t mnt;
	if (!addMountPt(&mnt, src, dst, fstype, options, flags, is_dir, is_mandatory, src_env,
		dst_env, src_content, is_symlink)) {
		return false;
	}
	nsjconf->mountpts.insert(nsjconf->mountpts.begin(), mnt);
	return true;
}

bool addMountPtTail(nsjconf_t* nsjconf, const std::string& src, const std::string& dst,
    const std::string& fstype, const std::string& options, uintptr_t flags, isDir_t is_dir,
    bool is_mandatory, const std::string& src_env, const std::string& dst_env,
    const std::string& src_content, bool is_symlink) {
	mount_t mnt;
	if (!addMountPt(&mnt, src, dst, fstype, options, flags, is_dir, is_mandatory, src_env,
		dst_env, src_content, is_symlink)) {
		return false;
	}
	nsjconf->mountpts.push_back(mnt);
	return true;
}

const std::string describeMountPt(const mount_t& mpt) {
	char mount_pt_descr[256];

	snprintf(mount_pt_descr, sizeof(mount_pt_descr),
	    "src:'%s' dst:'%s' type:'%s' flags:%s options:'%s' isDir:%s", mpt.src.c_str(),
	    mpt.dst.c_str(), mpt.fs_type.c_str(), flagsToStr(mpt.flags).c_str(),
	    mpt.options.c_str(), mpt.is_dir ? "true" : "false");

	if (!mpt.is_mandatory) {
		util::sSnPrintf(mount_pt_descr, sizeof(mount_pt_descr), " mandatory:false");
	}
	if (!mpt.src_content.empty()) {
		util::sSnPrintf(mount_pt_descr, sizeof(mount_pt_descr), " src_content_len:%zu",
		    mpt.src_content.length());
	}
	if (mpt.is_symlink) {
		util::sSnPrintf(mount_pt_descr, sizeof(mount_pt_descr), " symlink:true");
	}

	return mount_pt_descr;
}

}  // namespace mnt
