/*

   nsjail - cgroup namespacing
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

#include "cgroup.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

bool cgroupInitNs(struct nsjconf_t *nsjconf)
{
	if (nsjconf->clone_newcgroup == false) {
		return true;
	}

	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		PLOG_E("gettimeofday() failed");
		return false;
	}

	char mem_cgroup_path[PATH_MAX];
	snprintf(mem_cgroup_path, sizeof(mem_cgroup_path), "%s/%s/NSJAIL.%lx.%lx",
		 nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_parent, (unsigned long)tv.tv_sec,
		 (unsigned long)tv.tv_usec);
	if (mkdir(mem_cgroup_path, 0700) == -1) {
		PLOG_E("mkdir('%s', 0711) failed", mem_cgroup_path);
		return false;
	}

	char fname[PATH_MAX];
	if (nsjconf->cgroup_mem_max != (size_t) 0) {
		char mem_max_str[512];
		snprintf(mem_max_str, sizeof(mem_max_str), "%zu", nsjconf->cgroup_mem_max);
		snprintf(fname, sizeof(fname), "%s/memory.limit_in_bytes", mem_cgroup_path);
		LOG_D("Setting %s/memory.limit_in_bytes to '%s'", mem_cgroup_path, mem_max_str);
		if (utilWriteBufToFile(fname, mem_max_str, strlen(mem_max_str), O_WRONLY) == false) {
			LOG_E("Could not update memory cgroup max limit");
			return false;
		}
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%ld", syscall(__NR_getpid));
	snprintf(fname, sizeof(fname), "%s/tasks", mem_cgroup_path);
	LOG_D("Adding PID='%s' to %s/tasks", pid_str, mem_cgroup_path);
	if (utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY) == false) {
		LOG_E("Could not update memory cgroup task list");
		return false;
	}

	LOG_D("Unmounting '%s'", nsjconf->cgroup_mem_mount);
	if (umount2(nsjconf->cgroup_mem_mount, MNT_DETACH) == -1) {
		PLOG_E("Could not umount2('%s', MNT_DETACH)", nsjconf->cgroup_mem_mount);
		return false;
	}

	return true;
}
