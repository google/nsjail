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

#include "mount.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

static bool mountIsDir(const char *path)
{
	/*
	 *  If the source dir is NULL, we assume it's a dir (for /proc and tmpfs)
	 */
	if (path == NULL) {
		return true;
	}
	struct stat st;
	if (stat(path, &st) == -1) {
		PLOG_E("stat('%s')", path);
		return false;
	}
	if (S_ISDIR(st.st_mode)) {
		return true;
	}
	return false;
}

// It's a not a simple reversal of containIsDir() as it returns also 'false' upon
// stat() failure
static bool mountNotIsDir(const char *path)
{
	if (path == NULL) {
		return false;
	}
	struct stat st;
	if (stat(path, &st) == -1) {
		PLOG_E("stat('%s')", path);
		return false;
	}
	if (S_ISDIR(st.st_mode)) {
		return false;
	}
	return true;
}

static bool mountMount(struct nsjconf_t *nsjconf, struct mounts_t *mpt, const char *oldroot,
		       const char *dst)
{
	LOG_D("Mounting '%s' on '%s' (type:'%s', flags:0x%tx, options:'%s')", mpt->src, dst,
	      mpt->fs_type, mpt->flags, mpt->options);

	char srcpath[PATH_MAX];
	const char *src = NULL;
	if (mpt->src != NULL) {
		snprintf(srcpath, sizeof(srcpath), "%s/%s", oldroot, mpt->src);
		src = srcpath;
	}

	if (mountIsDir(src) == true) {
		if (utilCreateDirRecursively(dst) == false) {
			LOG_W("Couldn't create upper directories for '%s'", dst);
			return false;
		}
		if (mkdir(dst, 0711) == -1 && errno != EEXIST) {
			PLOG_W("mkdir('%s')", dst);
		}
	}

	if (mountNotIsDir(src) == true) {
		if (utilCreateDirRecursively(dst) == false) {
			LOG_W("Couldn't create upper directories for '%s'", dst);
			return false;
		}
		int fd = TEMP_FAILURE_RETRY(open(dst, O_CREAT | O_RDONLY | O_CLOEXEC, 0644));
		if (fd >= 0) {
			close(fd);
		} else {
			PLOG_W("open('%s', O_CREAT|O_RDONLY|O_CLOEXEC, 0700)", dst);
		}
	}

	/*
	 * Initially mount it as RW, it will be remounted later on if needed
	 */
	unsigned long flags = mpt->flags & ~(MS_RDONLY);
	if (mount(src, dst, mpt->fs_type, flags, mpt->options) == -1) {
		if (errno == EACCES) {
			PLOG_E
			    ("mount('%s', '%s', type='%s') failed. Try fixing this problem by applying 'chmod o+x' to the '%s' directory and its ancestors",
			     src, dst, mpt->fs_type, nsjconf->chroot);
		} else {
			PLOG_E("mount('%s', '%s', type='%s') failed", src, dst, mpt->fs_type);
		}
		return false;
	}
	return true;
}

static bool mountRemountRO(struct mounts_t *mpt)
{
	struct statvfs vfs;
	if (TEMP_FAILURE_RETRY(statvfs(mpt->dst, &vfs)) == -1) {
		PLOG_E("statvfs('%s')", mpt->dst);
		return false;
	}

	if (mpt->flags & MS_RDONLY) {
		LOG_D("Re-mounting RO '%s'", mpt->dst);
		/*
		 * It's fine to use 'flags | vfs.f_flag' here as per
		 * /usr/include/x86_64-linux-gnu/bits/statvfs.h: 'Definitions for
		 * the flag in `f_flag'.  These definitions should be
		 * kept in sync with the definitions in <sys/mount.h>'
		 */
		if (mount
		    (mpt->dst, mpt->dst, NULL,
		     MS_BIND | MS_REMOUNT | MS_RDONLY | vfs.f_flag, 0) == -1) {
			PLOG_E("mount('%s', MS_REC|MS_BIND|MS_REMOUNT|MS_RDONLY)", mpt->dst);
			return false;
		}
	}
	return true;
}

static bool mountInitNsInternal(struct nsjconf_t *nsjconf)
{
	if (nsjconf->clone_newns == false) {
		if (chroot(nsjconf->chroot) == -1) {
			PLOG_E("chroot('%s')", nsjconf->chroot) {
				return false;
			}
		}
		if (chdir("/") == -1) {
			PLOG_E("chdir('/')");
			return false;
		}
		return true;
	}

	const char *const destdir = "/tmp";
	if (mount(NULL, destdir, "tmpfs", 0, NULL) == -1) {
		PLOG_E("mount('%s', 'tmpfs'", destdir);
		return false;
	}
	char oldrootdir[PATH_MAX];
	snprintf(oldrootdir, sizeof(oldrootdir), "%s/old_root", destdir);
	if (mkdir(oldrootdir, 0755) == -1) {
		PLOG_E("mkdir('%s')", oldrootdir);
		return false;
	}
	if (syscall(__NR_pivot_root, destdir, oldrootdir) == -1) {
		PLOG_E("pivot_root('%s', '%s')", destdir, oldrootdir);
		return false;
	}
	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return false;
	}

	const char *newrootdir;
	if (nsjconf->pivot_root_only == false) {
		newrootdir = "/new_root";
		if (mkdir(newrootdir, 0755) == -1) {
			PLOG_E("mkdir('%s')", newrootdir);
			return false;
		}
	} else {
		newrootdir = "/";
	}

	struct mounts_t *p;
	TAILQ_FOREACH(p, &nsjconf->mountpts, pointers) {
		char dst[PATH_MAX];
		snprintf(dst, sizeof(dst), "%s/%s", newrootdir, p->dst);
		if (mountMount(nsjconf, p, "/old_root", dst) == false) {
			return false;
		}
	}

	if (umount2("/old_root", MNT_DETACH) == -1) {
		PLOG_E("umount2('/old_root', MNT_DETACH)");
		return false;
	}
	if (nsjconf->pivot_root_only == false) {
		if (chroot(newrootdir) == -1) {
			PLOG_E("chroot('%s')", newrootdir);
			return false;
		}
	} else {
		if (rmdir("/old_root") == -1) {
			PLOG_E("rmdir('/old_root')");
			return false;
		}
	}

	if (chdir(nsjconf->cwd) == -1) {
		PLOG_E("chdir('%s')", nsjconf->cwd);
		return false;
	}

	TAILQ_FOREACH(p, &nsjconf->mountpts, pointers) {
		if (mountRemountRO(p) == false) {
			return false;
		}
	}

	return true;
}

/*
 * With mode MODE_STANDALONE_EXECVE it's required to mount /proc inside a new process,
 *  as the current process is still in the original PID namespace (man pid_namespaces)
 */
bool mountInitNs(struct nsjconf_t * nsjconf)
{
	if (nsjconf->mode != MODE_STANDALONE_EXECVE) {
		return mountInitNsInternal(nsjconf);
	}

	pid_t pid =
	    syscall(__NR_clone, (uintptr_t) CLONE_FS | SIGCHLD, NULL, NULL, NULL, (uintptr_t) 0);
	if (pid == -1) {
		return false;
	}

	if (pid == 0) {
		exit(mountInitNsInternal(nsjconf) ? 0 : 1);
	}

	int status;
	while (wait4(pid, &status, 0, NULL) != pid) ;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return true;
	}
	return false;
}
