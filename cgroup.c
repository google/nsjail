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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

bool cgroupInitNs(struct nsjconf_t *nsjconf)
{
	if (nsjconf->clone_newcgroup == false) {
		return true;
	}

	char fname[PATH_MAX];
	if (nsjconf->cgroup_mem_max != (size_t) 0) {
		char mem_max_str[512];
		snprintf(mem_max_str, sizeof(mem_max_str), "%zu", nsjconf->cgroup_mem_max);
		snprintf(fname, sizeof(fname), "%s/%s/memory.limit_in_bytes",
			 nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_group);
		LOG_D("Setting %s/%s/memory.limit_in_bytes to '%s'", nsjconf->cgroup_mem_mount,
		      nsjconf->cgroup_mem_group, mem_max_str);
		if (utilWriteBufToFile(fname, mem_max_str, strlen(mem_max_str), O_WRONLY) == false) {
			LOG_E("Could not update memory cgroup max limit");
			return false;
		}
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%ld", syscall(__NR_getpid));
	snprintf(fname, sizeof(fname), "%s/%s/tasks", nsjconf->cgroup_mem_mount,
		 nsjconf->cgroup_mem_group);
	LOG_D("Adding PID='%s' to %s/%s/tasks", pid_str, nsjconf->cgroup_mem_mount,
	      nsjconf->cgroup_mem_group);
	if (utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY) == false) {
		LOG_E("Could not update memory cgroup task list");
		return false;
	}

	return true;
}
