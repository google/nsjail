/*

   nsjail - cgroup2 namespacing
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

#include "cgroup2.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "logs.h"
#include "util.h"

namespace cgroup2 {

static std::string getCgroupPath(nsjconf_t *nsjconf, pid_t pid) {
	return nsjconf->cgroupv2_mount + "/NSJAIL." + std::to_string(pid);
}

static bool createCgroup(const std::string &cgroup_path, pid_t pid) {
	LOG_D("Create '%s' for pid=%d", cgroup_path.c_str(), (int)pid);
	if (mkdir(cgroup_path.c_str(), 0700) == -1 && errno != EEXIST) {
		PLOG_W("mkdir('%s', 0700) failed", cgroup_path.c_str());
		return false;
	}
	return true;
}

static bool writeToCgroup(
    const std::string &cgroup_path, const std::string &resource, const std::string &value) {
	LOG_I("Setting '%s' to '%s'", resource.c_str(), value.c_str());

	if (!util::writeBufToFile(
		(cgroup_path + "/" + resource).c_str(), value.c_str(), value.length(), O_WRONLY)) {
		LOG_W("Could not update %s", resource.c_str());
		return false;
	}
	return true;
}

static bool addPidToProcList(const std::string &cgroup_path, pid_t pid) {
	std::string pid_str = std::to_string(pid);

	LOG_D("Adding pid='%s' to cgroup.procs", pid_str.c_str());
	if (!util::writeBufToFile((cgroup_path + "/cgroup.procs").c_str(), pid_str.c_str(),
		pid_str.length(), O_WRONLY)) {
		LOG_W("Could not update cgroup.procs");
		return false;
	}
	return true;
}

static void removeCgroup(const std::string &cgroup_path) {
	LOG_D("Remove '%s'", cgroup_path.c_str());
	if (rmdir(cgroup_path.c_str()) == -1) {
		PLOG_W("rmdir('%s') failed", cgroup_path.c_str());
	}
}

static bool initNsFromParentMem(nsjconf_t *nsjconf, pid_t pid) {
	ssize_t swap_max = nsjconf->cgroup_mem_swap_max;
	if (nsjconf->cgroup_mem_memsw_max > (size_t)0) {
		swap_max = nsjconf->cgroup_mem_memsw_max - nsjconf->cgroup_mem_max;
	}

	if (nsjconf->cgroup_mem_max == (size_t)0 && swap_max < (ssize_t)0) {
		return true;
	}

	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));

	if (nsjconf->cgroup_mem_max > (size_t)0) {
		RETURN_ON_FAILURE(writeToCgroup(
		    cgroup_path, "memory.max", std::to_string(nsjconf->cgroup_mem_max)));
	}

	if (swap_max >= (ssize_t)0) {
		RETURN_ON_FAILURE(
		    writeToCgroup(cgroup_path, "memory.swap.max", std::to_string(swap_max)));
	}

	return true;
}

static bool initNsFromParentPids(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_pids_max == 0U) {
		return true;
	}
	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));
	return writeToCgroup(cgroup_path, "pids.max", std::to_string(nsjconf->cgroup_pids_max));
}

static bool initNsFromParentCpu(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
		return true;
	}

	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));

	// The maximum bandwidth limit in the format: `$MAX $PERIOD`.
	// This indicates that the group may consume up to $MAX in each $PERIOD
	// duration.
	std::string cpu_ms_per_sec_str = std::to_string(nsjconf->cgroup_cpu_ms_per_sec * 1000U);
	cpu_ms_per_sec_str += " 1000000";
	return writeToCgroup(cgroup_path, "cpu.max", cpu_ms_per_sec_str);
}

bool initNsFromParent(nsjconf_t *nsjconf, pid_t pid) {
	RETURN_ON_FAILURE(initNsFromParentMem(nsjconf, pid));
	RETURN_ON_FAILURE(initNsFromParentPids(nsjconf, pid));
	return initNsFromParentCpu(nsjconf, pid);
}

void finishFromParent(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max != (size_t)0 || nsjconf->cgroup_pids_max != 0U ||
	    nsjconf->cgroup_cpu_ms_per_sec != 0U) {
		removeCgroup(getCgroupPath(nsjconf, pid));
	}
}

}  // namespace cgroup2
