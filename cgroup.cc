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
	LOG_D("Create %s for pid=%d", QC(cgroup_path), (int)pid);
	if (mkdir(cgroup_path.c_str(), 0700) == -1 && errno != EEXIST) {
		PLOG_W("mkdir(%s, 0700) failed", QC(cgroup_path));
		return false;
	}
	return true;
}

static bool writeToCgroup(
    const std::string& cgroup_path, const std::string& value, const std::string& what) {
	LOG_D("Setting %s to '%s'", QC(cgroup_path), value.c_str());
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
	LOG_D("Adding pid='%s' to %s", pid_str.c_str(), QC(tasks_path));
	return writeToCgroup(tasks_path, pid_str, "'" + tasks_path + "' task list");
}

static bool initNsFromParentMem(nsj_t* nsj, pid_t pid) {
	size_t memsw_max = nsj->njc.cgroup_mem_memsw_max();
	if (nsj->njc.cgroup_mem_swap_max() >= (ssize_t)0) {
		memsw_max = nsj->njc.cgroup_mem_swap_max() + nsj->njc.cgroup_mem_max();
	}

	if (nsj->njc.cgroup_mem_max() == (size_t)0 && memsw_max == (size_t)0) {
		return true;
	}

	std::string mem_cgroup_path = nsj->njc.cgroup_mem_mount() + '/' +
				      nsj->njc.cgroup_mem_parent() + "/NSJAIL." +
				      std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(mem_cgroup_path, pid));

	/*
	 * Use OOM-killer instead of making processes hang/sleep
	 */
	RETURN_ON_FAILURE(writeToCgroup(
	    mem_cgroup_path + "/memory.oom_control", "0", "memory cgroup oom control"));

	if (nsj->njc.cgroup_mem_max() > (size_t)0) {
		std::string mem_max_str = std::to_string(nsj->njc.cgroup_mem_max());
		RETURN_ON_FAILURE(writeToCgroup(mem_cgroup_path + "/memory.limit_in_bytes",
		    mem_max_str, "memory cgroup max limit"));
	}

	if (memsw_max > (size_t)0) {
		std::string mem_memsw_max_str = std::to_string(memsw_max);
		RETURN_ON_FAILURE(writeToCgroup(mem_cgroup_path + "/memory.memsw.limit_in_bytes",
		    mem_memsw_max_str, "memory+Swap cgroup max limit"));
	}

	return addPidToTaskList(mem_cgroup_path, pid);
}

static bool initNsFromParentPids(nsj_t* nsj, pid_t pid) {
	if (nsj->njc.cgroup_pids_max() == 0U) {
		return true;
	}

	std::string pids_cgroup_path = nsj->njc.cgroup_pids_mount() + '/' +
				       nsj->njc.cgroup_pids_parent() + "/NSJAIL." +
				       std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(pids_cgroup_path, pid));

	std::string pids_max_str = std::to_string(nsj->njc.cgroup_pids_max());
	RETURN_ON_FAILURE(
	    writeToCgroup(pids_cgroup_path + "/pids.max", pids_max_str, "pids cgroup max limit"));

	return addPidToTaskList(pids_cgroup_path, pid);
}

static bool initNsFromParentNetCls(nsj_t* nsj, pid_t pid) {
	if (nsj->njc.cgroup_net_cls_classid() == 0U) {
		return true;
	}

	std::string net_cls_cgroup_path = nsj->njc.cgroup_net_cls_mount() + '/' +
					  nsj->njc.cgroup_net_cls_parent() + "/NSJAIL." +
					  std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(net_cls_cgroup_path, pid));

	std::string net_cls_classid_str;
	{
		std::stringstream ss;
		ss << "0x" << std::hex << nsj->njc.cgroup_net_cls_classid();
		net_cls_classid_str = ss.str();
	}
	RETURN_ON_FAILURE(writeToCgroup(net_cls_cgroup_path + "/net_cls.classid",
	    net_cls_classid_str, "net_cls cgroup classid"));

	return addPidToTaskList(net_cls_cgroup_path, pid);
}

static bool initNsFromParentCpu(nsj_t* nsj, pid_t pid) {
	if (nsj->njc.cgroup_cpu_ms_per_sec() == 0U) {
		return true;
	}

	std::string cpu_cgroup_path = nsj->njc.cgroup_cpu_mount() + '/' +
				      nsj->njc.cgroup_cpu_parent() + "/NSJAIL." +
				      std::to_string(pid);
	RETURN_ON_FAILURE(createCgroup(cpu_cgroup_path, pid));

	RETURN_ON_FAILURE(
	    writeToCgroup(cpu_cgroup_path + "/cpu.cfs_period_us", "1000000", "cpu period"));

	std::string cpu_ms_per_sec_str = std::to_string(nsj->njc.cgroup_cpu_ms_per_sec() * 1000U);
	RETURN_ON_FAILURE(
	    writeToCgroup(cpu_cgroup_path + "/cpu.cfs_quota_us", cpu_ms_per_sec_str, "cpu quota"));

	return addPidToTaskList(cpu_cgroup_path, pid);
}

bool initNsFromParent(nsj_t* nsj, pid_t pid) {
	RETURN_ON_FAILURE(initNsFromParentMem(nsj, pid));
	RETURN_ON_FAILURE(initNsFromParentPids(nsj, pid));
	RETURN_ON_FAILURE(initNsFromParentNetCls(nsj, pid));
	return initNsFromParentCpu(nsj, pid);
}

static void removeCgroup(const std::string& cgroup_path) {
	LOG_D("Remove %s", QC(cgroup_path));
	if (rmdir(cgroup_path.c_str()) == -1) {
		PLOG_W("rmdir(%s) failed", QC(cgroup_path));
	}
}

void finishFromParent(nsj_t* nsj, pid_t pid) {
	if (nsj->njc.cgroup_mem_max() != (size_t)0 ||
	    nsj->njc.cgroup_mem_memsw_max() != (size_t)0) {
		std::string mem_cgroup_path = nsj->njc.cgroup_mem_mount() + '/' +
					      nsj->njc.cgroup_mem_parent() + "/NSJAIL." +
					      std::to_string(pid);
		removeCgroup(mem_cgroup_path);
	}
	if (nsj->njc.cgroup_pids_max() != 0U) {
		std::string pids_cgroup_path = nsj->njc.cgroup_pids_mount() + '/' +
					       nsj->njc.cgroup_pids_parent() + "/NSJAIL." +
					       std::to_string(pid);
		removeCgroup(pids_cgroup_path);
	}
	if (nsj->njc.cgroup_net_cls_classid() != 0U) {
		std::string net_cls_cgroup_path = nsj->njc.cgroup_net_cls_mount() + '/' +
						  nsj->njc.cgroup_net_cls_parent() + "/NSJAIL." +
						  std::to_string(pid);
		removeCgroup(net_cls_cgroup_path);
	}
	if (nsj->njc.cgroup_cpu_ms_per_sec() != 0U) {
		std::string cpu_cgroup_path = nsj->njc.cgroup_cpu_mount() + '/' +
					      nsj->njc.cgroup_cpu_parent() + "/NSJAIL." +
					      std::to_string(pid);
		removeCgroup(cpu_cgroup_path);
	}
}

bool initUser(nsj_t* nsj) {
	return true;
}

bool initNs() {
	return true;
}

}  // namespace cgroup
