/*

   nsjail - isolating the binary
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
#include "contain.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "log.h"

static bool containSetGroups(void)
{
	int fd = open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
	if (fd == -1) {
		/* Not present with all kernels */
		PLOG_D("'/proc/self/setgroups' not present in this kernel?");
		return true;
	}
	const char *denystr = "deny";
	if (write(fd, denystr, strlen(denystr)) == -1) {
		PLOG_E("write('/proc/self/setgroups', '%s') failed", denystr);
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

static bool containUidGidMap(struct nsjconf_t *nsjconf, uid_t uid, gid_t gid)
{
	if (nsjconf->clone_newuser == false) {
		return true;
	}

	int fd;
	char map[64];
	if ((fd = open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC)) == -1) {
		PLOG_E("open('/proc/self/uid_map', O_WRONLY | O_CLOEXEC)");
		return false;
	}
	snprintf(map, sizeof(map), "%lu %lu 1", (unsigned long)uid, (unsigned long)nsjconf->initial_uid);
	LOG_D("Writing '%s' to /proc/self/uid_map", map);
	if (write(fd, map, strlen(map)) == -1) {
		PLOG_E("write('/proc/self/uid_map', %d, '%s')", fd, map);
		close(fd);
		return false;
	}
	close(fd);

	if ((fd = open("/proc/self/gid_map", O_WRONLY | O_CLOEXEC)) == -1) {
		PLOG_E("open('/proc/self/gid_map', O_WRONLY | O_CLOEXEC)");
		return false;
	}
	snprintf(map, sizeof(map), "%lu %lu 1", (unsigned long)gid, (unsigned long)nsjconf->initial_gid);
	LOG_D("Writing '%s' to /proc/self/gid_map", map);
	if (write(fd, map, strlen(map)) == -1) {
		PLOG_E("write('/proc/self/gid_map', %d, '%s')", fd, map);
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

bool containDropPrivs(struct nsjconf_t * nsjconf)
{
	if (containSetGroups() == false) {
		return false;
	}
	if (containUidGidMap(nsjconf, nsjconf->uid, nsjconf->gid) == false) {
		return false;
	}
	/*
	 * Best effort because of /proc/self/setgroups
	 */
	gid_t *group_list = NULL;
	if (setgroups(0, group_list) == -1) {
		PLOG_D("setgroups(NULL) failed");
	}
	if (setresgid(nsjconf->gid, nsjconf->gid, nsjconf->gid) == -1) {
		PLOG_E("setresgid(%u)", nsjconf->gid);
		return false;
	}
	if (setresuid(nsjconf->uid, nsjconf->uid, nsjconf->uid) == -1) {
		PLOG_E("setresuid(%u)", nsjconf->uid);
		return false;
	}
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		/* Only new kernels support it */
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1)");
	}

	if (nsjconf->keep_caps == false) {
		if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) == -1) {
			PLOG_E("prctl(PR_SET_KEEPCAPS, 0)");
			return false;
		}
		struct __user_cap_header_struct cap_hdr = {
			.version = _LINUX_CAPABILITY_VERSION_3,
			.pid = 0,
		};
		struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3] = {
			[0 ... (_LINUX_CAPABILITY_U32S_3 - 1)].inheritable = 0U,
			[0 ... (_LINUX_CAPABILITY_U32S_3 - 1)].effective = 0U,
			[0 ... (_LINUX_CAPABILITY_U32S_3 - 1)].permitted = 0U,
		};
		if (syscall(__NR_capset, &cap_hdr, &cap_data) == -1) {
			PLOG_E("capset()");
			return false;
		}
	}
	return true;
}

bool containPrepareEnv(struct nsjconf_t * nsjconf)
{
	LOG_D("Setting hostname to '%s'", nsjconf->hostname);
	if (nsjconf->clone_newuts) {
		if (sethostname(nsjconf->hostname, strlen(nsjconf->hostname)) == -1) {
			PLOG_E("sethostname('%s')", nsjconf->hostname);
			return false;
		}
	}
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL)");
		return false;
	}
	if (nsjconf->personality && personality(nsjconf->personality) == -1) {
		PLOG_E("personality(%lx)", nsjconf->personality);
		return false;
	}
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, 19) == -1 && errno != 0) {
		PLOG_W("setpriority(19)");
	}
	return true;
}

/* findSpecDestination mutates spec (source:dest) to have a null byte instead
 * of ':' in between source and dest, then returns a pointer to the dest
 * string. */
static char *findSpecDestination(char *spec) {
	char *dest = spec;
	while (*dest != ':' && *dest != '\0') {
		dest++;
	}

	switch (*dest) {
	case ':':
		*dest = '\0';
		return dest + 1;
	case '\0':
		return spec;
	default:
		// not reached
		return spec;
	}
}

static bool bindMount(const char *newrootdir, const char *spec) {
	char mount_pt[PATH_MAX];
	bool success = false;
	char *source = strdup(spec);
	char *dest = findSpecDestination(source);

	snprintf(mount_pt, sizeof(mount_pt), "%s/%s", newrootdir, dest);
	if (mkdir(mount_pt, 0700) == -1 && errno != EEXIST) {
		PLOG_E("mkdir('%s')", mount_pt);
		goto cleanup;
	}
	LOG_D("Mounting (bind) '%s' on '%s'", source, mount_pt);
	if (mount(source, mount_pt, NULL, MS_BIND | MS_REC, NULL) == -1) {
		PLOG_E("mount('%s', '%s', MS_BIND|MS_REC)", source, mount_pt);
		goto cleanup;
	}
	success = true;

cleanup:
	free(source);
	return success;
}

static bool remountBindMount(const char *spec, unsigned long flags) {
	bool success = false;
	char *source = strdup(spec);
	char *dest = findSpecDestination(source);

	LOG_D("Remounting (bind|%lu) '%s' on '%s'", flags, dest, dest);
	if (mount(dest, dest, NULL, MS_BIND | MS_NOSUID | MS_REMOUNT | MS_PRIVATE | flags, NULL) == -1) {
		PLOG_E("mount('%s', '%s', MS_BIND|MS_NOSUID|MS_REMOUNT|MS_PRIVATE|%lu)", dest, dest, flags);
		goto cleanup;
	}
	success = true;

cleanup:
	free(source);
	return success;
}

bool containMountFS(struct nsjconf_t * nsjconf)
{
	const char *destdir = "/tmp";
	if (mount("none", destdir, "tmpfs", 0, NULL) == -1) {
		PLOG_E("mount('%s', 'tmpfs'", destdir);
		return false;
	}
	char newrootdir[PATH_MAX];
	snprintf(newrootdir, sizeof(newrootdir), "%s/%s", destdir, "new_root");
	if (mkdir(newrootdir, 0755) == -1) {
		PLOG_E("mkdir(/tmp/new_root)");
		return false;
	}
	if (mount(nsjconf->chroot, newrootdir, NULL, MS_BIND | MS_REC, NULL) == -1) {
		PLOG_E("mount('%s', '%s', MS_BIND | MS_REC)", nsjconf->chroot, newrootdir);
		return false;
	}

	struct constchar_t *p;
	LIST_FOREACH(p, &nsjconf->robindmountpts, pointers) {
		if (!bindMount(newrootdir, p->value)) {
			return false;
		}
	}
	LIST_FOREACH(p, &nsjconf->rwbindmountpts, pointers) {
		if (!bindMount(newrootdir, p->value)) {
			return false;
		}
	}

	char pivotrootdir[PATH_MAX];
	snprintf(pivotrootdir, sizeof(pivotrootdir), "%s/%s", destdir, "pivot_root");
	if (mkdir(pivotrootdir, 0755) == -1) {
		PLOG_E("mkdir('%s')", pivotrootdir);
		return false;
	}
	if (syscall(__NR_pivot_root, destdir, pivotrootdir) == -1) {
		PLOG_E("pivot_root('%s', '%s')", destdir, pivotrootdir);
		return false;
	}

	char procrootdir[PATH_MAX] = "/new_root/proc";
	if (mount(NULL, procrootdir, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == -1) {
		PLOG_E("mount('%s', 'proc')", procrootdir);
		return false;
	}
	if (umount2("/pivot_root", MNT_DETACH) == -1) {
		PLOG_E("umount2('/pivot_root', MNT_DETACH)");
		return false;
	}
	if (chroot("/new_root") == -1) {
		PLOG_E("CHROOT('/new_root')");
		return false;
	}

	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return false;
	}
	/* It only makes sense with "--chroot /", so don't worry about errors */
	umount2(destdir, MNT_DETACH);

	char tmpfs_size[11+5];
	snprintf(tmpfs_size, sizeof(tmpfs_size), "size=%u", nsjconf->tmpfs_size);
	LIST_FOREACH(p, &nsjconf->tmpfsmountpts, pointers) {
		if (strchr(p->value, ':') != NULL) {
			PLOG_E("invalid tmpfs mount spec. source:dest format unsupported.");
			return false;
		}
		if (mkdir(p->value, 0700) == -1 && errno != EEXIST) {
			PLOG_E("mkdir('%s'); You probably need to create it in your --chroot ('%s') directory",
			       p->value, nsjconf->chroot);
			return false;
		}
		LOG_D("Mounting (tmpfs) '%s'", p->value);
		if (mount(NULL, p->value, "tmpfs", 0, tmpfs_size) == -1) {
			PLOG_E("mount('%s', 'tmpfs')", p->value);
			return false;
		}
	}

	if (nsjconf->is_root_rw == false) {
		if (mount
		    ("/", "/", NULL, MS_BIND | MS_RDONLY | MS_NOSUID | MS_REMOUNT | MS_PRIVATE,
		     NULL) == -1) {
			PLOG_E("mount('/', '/', MS_BIND|MS_RDONLY|MS_NOSUID|MS_REMOUNT|MS_PRIVATE)");
			return false;
		}
	}

	LIST_FOREACH(p, &nsjconf->robindmountpts, pointers) {
		if (!remountBindMount(p->value, MS_RDONLY)) {
			return false;
		}
	}
	LIST_FOREACH(p, &nsjconf->rwbindmountpts, pointers) {
		if (!remountBindMount(p->value, 0)) {
			return false;
		}
	}


	return true;
}

bool containSetLimits(struct nsjconf_t * nsjconf)
{
	struct rlimit rl;
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_as;
	if (setrlimit(RLIMIT_AS, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_AS, %lu)", nsjconf->rl_as);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_core;
	if (setrlimit(RLIMIT_CORE, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_CORE, %lu)", nsjconf->rl_core);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_cpu;
	if (setrlimit(RLIMIT_CPU, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_CPU), %lu", nsjconf->rl_cpu);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_fsize;
	if (setrlimit(RLIMIT_FSIZE, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_FSIZE), %lu", nsjconf->rl_fsize);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_nofile;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_NOFILE), %lu", nsjconf->rl_nofile);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_nproc;
	if (setrlimit(RLIMIT_NPROC, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_NPROC), %lu", nsjconf->rl_nproc);
		return false;
	}
	rl.rlim_cur = rl.rlim_max = nsjconf->rl_stack;
	if (setrlimit(RLIMIT_STACK, &rl) == -1) {
		PLOG_E("setrlimit(RLIMIT_STACK), %lu", nsjconf->rl_stack);
		return false;
	}
	return true;
}

bool containMakeFdsCOE(void)
{
	/* Make all fds above stderr close-on-exec */
	DIR *dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		PLOG_E("opendir('/proc/self/fd')");
		return false;
	}
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(dir);
		if (entry == NULL && errno != 0) {
			PLOG_E("readdir('/proc/self/fd')");
			closedir(dir);
			return false;
		}
		if (entry == NULL) {
			break;
		}
		if (strcmp(".", entry->d_name) == 0) {
			continue;
		}
		if (strcmp("..", entry->d_name) == 0) {
			continue;
		}
		int fd = strtoul(entry->d_name, NULL, 10);
		if (errno == EINVAL) {
			LOG_W("Cannot convert /proc/self/fd/%s to a number", entry->d_name);
			continue;
		}
		if (fd > STDERR_FILENO) {
			int flags = fcntl(fd, F_GETFD, 0);
			if (flags == -1) {
				PLOG_E("fcntl(fd, F_GETFD, 0)");
				return false;
			}
			fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
			LOG_D("Set fd '%d' flag to FD_CLOEXEC", fd);
		}
	}
	closedir(dir);
	return true;
}

bool containSetupFD(struct nsjconf_t * nsjconf, int fd_in, int fd_out, int fd_err, int fd_log)
{
	/* Make sure all logs go to the parent process from now on */
	logRedirectLogFD(fd_log);

	if (nsjconf->mode != MODE_LISTEN_TCP) {
		if (nsjconf->is_silent == false) {
			return true;
		}
		if ((fd_in = fd_out = fd_err = open("/dev/null", O_RDWR)) == -1) {
			PLOG_E("open('/dev/null', O_RDWR)");
			return false;
		}
	}
	/* Set stdin/stdout/stderr to the net */
	if (dup2(fd_in, STDIN_FILENO) == -1) {
		PLOG_E("dup2(%d, STDIN_FILENO)", fd_in);
		return false;
	}
	if (dup2(fd_out, STDOUT_FILENO) == -1) {
		PLOG_E("dup2(%d, STDOUT_FILENO)", fd_out);
		return false;
	}
	if (dup2(fd_err, STDERR_FILENO) == -1) {
		PLOG_E("dup2(%d, STDERR_FILENO)", fd_err);
		return false;
	}
	return true;
}
