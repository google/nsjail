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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>

#include "logs.h"
#include "util.h"

namespace cgroup {

static bool createCgroup(const std::string& cgroup_path, pid_t pid) {
	LOG_D("Create '%s' for pid=%d", cgroup_path.c_str(), (int)pid);
	if (mkdir(cgroup_path.c_str(), 0700) == -1 && errno != EEXIST) {
		PLOG_W("mkdir('%s', 0700) failed", cgroup_path.c_str());
		return false;
	}
	return true;
}

static bool writeToCgroup(
    const std::string& cgroup_path, const std::string& value, const std::string& what) {
	LOG_D("Setting '%s' to '%s'", cgroup_path.c_str(), value.c_str());
	if (!util::writeBufToFile(
		cgroup_path.c_str(), value.c_str(), value.length(), O_WRONLY | O_CLOEXEC)) {
		LOG_W("Could not update %s", what.c_str());
		return false;
	}
	return true;
}

static bool addPidToTaskList(const std::string& cgroup_path, pid_t pid) {
	std::string pid_str = std::to_string(pid);
	std::string tasks_path = cgroup_path + "/tasks";
	LOG_D("Adding pid='%s' to '%s'", pid_str.c_str(), tasks_path.c_str());
	return writeToCgroup(tasks_path, pid_str, "'" + tasks_path + "' task list");
}

static bool initNsFromParentMem(nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max == (size_t)0) {
		return true;
	}

	std::string mem_cgroup_path = nsjconf->cgroup_mem_mount + '/' + nsjconf->cgroup_mem_parent +
				      "/NSJAIL." + std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(mem_cgroup_path, pid));

	std::string mem_max_str = std::to_string(nsjconf->cgroup_mem_max);
	RETURN_ON_FAILURE(writeToCgroup(
	    mem_cgroup_path + "/memory.limit_in_bytes", mem_max_str, "memory cgroup max limit"));

	/*
	 * Use OOM-killer instead of making processes hang/sleep
	 */
	RETURN_ON_FAILURE(writeToCgroup(
	    mem_cgroup_path + "/memory.oom_control", "0", "memory cgroup oom control"));

	return addPidToTaskList(mem_cgroup_path, pid);
}

static bool initNsFromParentPids(nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_pids_max == 0U) {
		return true;
	}

	std::string pids_cgroup_path = nsjconf->cgroup_pids_mount + '/' +
				       nsjconf->cgroup_pids_parent + "/NSJAIL." +
				       std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(pids_cgroup_path, pid));

	std::string pids_max_str = std::to_string(nsjconf->cgroup_pids_max);
	RETURN_ON_FAILURE(
	    writeToCgroup(pids_cgroup_path + "/pids.max", pids_max_str, "pids cgroup max limit"));

	return addPidToTaskList(pids_cgroup_path, pid);
}

static bool initNsFromParentNetCls(nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_net_cls_classid == 0U) {
		return true;
	}

	std::string net_cls_cgroup_path = nsjconf->cgroup_net_cls_mount + '/' +
					  nsjconf->cgroup_net_cls_parent + "/NSJAIL." +
					  std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(net_cls_cgroup_path, pid));

	std::string net_cls_classid_str;
	{
		std::stringstream ss;
		ss << "0x" << std::hex << nsjconf->cgroup_net_cls_classid;
		net_cls_classid_str = ss.str();
	}
	RETURN_ON_FAILURE(writeToCgroup(net_cls_cgroup_path + "/net_cls.classid",
	    net_cls_classid_str, "net_cls cgroup classid"));

	return addPidToTaskList(net_cls_cgroup_path, pid);
}

static bool initNsFromParentCpu(nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
		return true;
	}

	std::string cpu_cgroup_path = nsjconf->cgroup_cpu_mount + '/' + nsjconf->cgroup_cpu_parent +
				      "/NSJAIL." + std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(cpu_cgroup_path, pid));

	std::string cpu_ms_per_sec_str = std::to_string(nsjconf->cgroup_cpu_ms_per_sec * 1000U);
	RETURN_ON_FAILURE(
	    writeToCgroup(cpu_cgroup_path + "/cpu.cfs_quota_us", cpu_ms_per_sec_str, "cpu quota"));

	RETURN_ON_FAILURE(
	    writeToCgroup(cpu_cgroup_path + "/cpu.cfs_period_us", "1000000", "cpu period"));

	return addPidToTaskList(cpu_cgroup_path, pid);
}

bool initNsFromParent(nsjconf_t* nsjconf, pid_t pid) {
	RETURN_ON_FAILURE(initNsFromParentMem(nsjconf, pid));
	RETURN_ON_FAILURE(initNsFromParentPids(nsjconf, pid));
	RETURN_ON_FAILURE(initNsFromParentNetCls(nsjconf, pid));
	return initNsFromParentCpu(nsjconf, pid);
}

static void removeCgroup(const std::string& cgroup_path) {
	LOG_D("Remove '%s'", cgroup_path.c_str());
	if (rmdir(cgroup_path.c_str()) == -1) {
		PLOG_W("rmdir('%s') failed", cgroup_path.c_str());
	}
}

void finishFromParent(nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max != (size_t)0) {
		std::string mem_cgroup_path = nsjconf->cgroup_mem_mount + '/' +
					      nsjconf->cgroup_mem_parent + "/NSJAIL." +
					      std::to_string(pid);
		removeCgroup(mem_cgroup_path);
	}
	if (nsjconf->cgroup_pids_max != 0U) {
		std::string pids_cgroup_path = nsjconf->cgroup_pids_mount + '/' +
					       nsjconf->cgroup_pids_parent + "/NSJAIL." +
					       std::to_string(pid);
		removeCgroup(pids_cgroup_path);
	}
	if (nsjconf->cgroup_net_cls_classid != 0U) {
		std::string net_cls_cgroup_path = nsjconf->cgroup_net_cls_mount + '/' +
						  nsjconf->cgroup_net_cls_parent + "/NSJAIL." +
						  std::to_string(pid);
		removeCgroup(net_cls_cgroup_path);
	}
	if (nsjconf->cgroup_cpu_ms_per_sec != 0U) {
		std::string cpu_cgroup_path = nsjconf->cgroup_cpu_mount + '/' +
					      nsjconf->cgroup_cpu_parent + "/NSJAIL." +
					      std::to_string(pid);
		removeCgroup(cpu_cgroup_path);
	}
}

bool initNs(void) {
	return true;
}

}  // namespace cgroup
