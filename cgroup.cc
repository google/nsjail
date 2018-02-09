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

extern "C" {
#include "log.h"
#include "util.h"
}

namespace cgroup {

static bool initNsFromParentMem(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max == (size_t)0) {
		return true;
	}

	char mem_cgroup_path[PATH_MAX];
	snprintf(mem_cgroup_path, sizeof(mem_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_parent, (int)pid);
	LOG_D("Create '%s' for PID=%d", mem_cgroup_path, (int)pid);
	if (mkdir(mem_cgroup_path, 0700) == -1 && errno != EEXIST) {
		PLOG_E("mkdir('%s', 0700) failed", mem_cgroup_path);
		return false;
	}

	char fname[PATH_MAX];
	char mem_max_str[512];
	snprintf(mem_max_str, sizeof(mem_max_str), "%zu", nsjconf->cgroup_mem_max);
	snprintf(fname, sizeof(fname), "%s/memory.limit_in_bytes", mem_cgroup_path);
	LOG_D("Setting '%s' to '%s'", fname, mem_max_str);
	if (!utilWriteBufToFile(fname, mem_max_str, strlen(mem_max_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update memory cgroup max limit");
		return false;
	}

	/*
	 * Use OOM-killer instead of making processes hang/sleep
	 */
	snprintf(fname, sizeof(fname), "%s/memory.oom_control", mem_cgroup_path);
	LOG_D("Writting '0' '%s'", fname);
	if (!utilWriteBufToFile(fname, "0", strlen("0"), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update memory cgroup oom control");
		return false;
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);
	snprintf(fname, sizeof(fname), "%s/tasks", mem_cgroup_path);
	LOG_D("Adding PID='%s' to '%s'", pid_str, fname);
	if (!utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update memory cgroup task list");
		return false;
	}

	return true;
}

static bool initNsFromParentPids(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_pids_max == 0U) {
		return true;
	}

	char pids_cgroup_path[PATH_MAX];
	snprintf(pids_cgroup_path, sizeof(pids_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_pids_mount, nsjconf->cgroup_pids_parent, (int)pid);
	LOG_D("Create '%s' for PID=%d", pids_cgroup_path, (int)pid);
	if (mkdir(pids_cgroup_path, 0700) == -1 && errno != EEXIST) {
		PLOG_E("mkdir('%s', 0700) failed", pids_cgroup_path);
		return false;
	}

	char fname[PATH_MAX];
	char pids_max_str[512];
	snprintf(pids_max_str, sizeof(pids_max_str), "%u", nsjconf->cgroup_pids_max);
	snprintf(fname, sizeof(fname), "%s/pids.max", pids_cgroup_path);
	LOG_D("Setting '%s' to '%s'", fname, pids_max_str);
	if (!utilWriteBufToFile(fname, pids_max_str, strlen(pids_max_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update pids cgroup max limit");
		return false;
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);
	snprintf(fname, sizeof(fname), "%s/tasks", pids_cgroup_path);
	LOG_D("Adding PID='%s' to '%s'", pid_str, fname);
	if (!utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update pids cgroup task list");
		return false;
	}

	return true;
}

static bool initNsFromParentNetCls(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_net_cls_classid == 0U) {
		return true;
	}

	char net_cls_cgroup_path[PATH_MAX];
	snprintf(net_cls_cgroup_path, sizeof(net_cls_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_net_cls_mount, nsjconf->cgroup_net_cls_parent, (int)pid);
	LOG_D("Create '%s' for PID=%d", net_cls_cgroup_path, (int)pid);
	if (mkdir(net_cls_cgroup_path, 0700) == -1 && errno != EEXIST) {
		PLOG_E("mkdir('%s', 0700) failed", net_cls_cgroup_path);
		return false;
	}

	char fname[PATH_MAX];
	char net_cls_classid_str[512];
	snprintf(net_cls_classid_str, sizeof(net_cls_classid_str), "0x%x",
	    nsjconf->cgroup_net_cls_classid);
	snprintf(fname, sizeof(fname), "%s/net_cls.classid", net_cls_cgroup_path);
	LOG_D("Setting '%s' to '%s'", fname, net_cls_classid_str);
	if (!utilWriteBufToFile(
		fname, net_cls_classid_str, strlen(net_cls_classid_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update net_cls cgroup classid");
		return false;
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);
	snprintf(fname, sizeof(fname), "%s/tasks", net_cls_cgroup_path);
	LOG_D("Adding PID='%s' to '%s'", pid_str, fname);
	if (!utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update net_cls cgroup task list");
		return false;
	}

	return true;
}

static bool initNsFromParentCpu(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
		return true;
	}

	char cpu_cgroup_path[PATH_MAX];
	snprintf(cpu_cgroup_path, sizeof(cpu_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_cpu_mount, nsjconf->cgroup_cpu_parent, (int)pid);
	LOG_D("Create '%s' for PID=%d", cpu_cgroup_path, (int)pid);
	if (mkdir(cpu_cgroup_path, 0700) == -1 && errno != EEXIST) {
		PLOG_E("mkdir('%s', 0700) failed", cpu_cgroup_path);
		return false;
	}

	char fname[PATH_MAX];
	char cpu_ms_per_sec_str[512];
	snprintf(cpu_ms_per_sec_str, sizeof(cpu_ms_per_sec_str), "%u",
	    nsjconf->cgroup_cpu_ms_per_sec * 1000U);
	snprintf(fname, sizeof(fname), "%s/cpu.cfs_quota_us", cpu_cgroup_path);
	LOG_D("Setting '%s' to '%s'", fname, cpu_ms_per_sec_str);
	if (!utilWriteBufToFile(
		fname, cpu_ms_per_sec_str, strlen(cpu_ms_per_sec_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update cpu quota");
		return false;
	}

	const char cpu_period_us[] = "1000000";
	snprintf(fname, sizeof(fname), "%s/cpu.cfs_period_us", cpu_cgroup_path);
	LOG_D("Setting '%s' to '%s'", fname, cpu_period_us);
	if (!utilWriteBufToFile(
		fname, cpu_period_us, strlen(cpu_period_us), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update cpu period");
		return false;
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);
	snprintf(fname, sizeof(fname), "%s/tasks", cpu_cgroup_path);
	LOG_D("Adding PID='%s' to '%s'", pid_str, fname);
	if (!utilWriteBufToFile(fname, pid_str, strlen(pid_str), O_WRONLY | O_CLOEXEC)) {
		LOG_E("Could not update cpu cgroup task list");
		return false;
	}

	return true;
}

bool initNsFromParent(struct nsjconf_t* nsjconf, pid_t pid) {
	if (!initNsFromParentMem(nsjconf, pid)) {
		return false;
	}
	if (!initNsFromParentPids(nsjconf, pid)) {
		return false;
	}
	if (!initNsFromParentNetCls(nsjconf, pid)) {
		return false;
	}
	if (!initNsFromParentCpu(nsjconf, pid)) {
		return false;
	}
	return true;
}

void finishFromParentMem(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max == (size_t)0) {
		return;
	}
	char mem_cgroup_path[PATH_MAX];
	snprintf(mem_cgroup_path, sizeof(mem_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_parent, (int)pid);
	LOG_D("Remove '%s'", mem_cgroup_path);
	if (rmdir(mem_cgroup_path) == -1) {
		PLOG_W("rmdir('%s') failed", mem_cgroup_path);
	}
	return;
}

void finishFromParentPids(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_pids_max == 0U) {
		return;
	}
	char pids_cgroup_path[PATH_MAX];
	snprintf(pids_cgroup_path, sizeof(pids_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_pids_mount, nsjconf->cgroup_pids_parent, (int)pid);
	LOG_D("Remove '%s'", pids_cgroup_path);
	if (rmdir(pids_cgroup_path) == -1) {
		PLOG_W("rmdir('%s') failed", pids_cgroup_path);
	}
	return;
}

void finishFromParentCpu(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
		return;
	}
	char cpu_cgroup_path[PATH_MAX];
	snprintf(cpu_cgroup_path, sizeof(cpu_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_cpu_mount, nsjconf->cgroup_cpu_parent, (int)pid);
	LOG_D("Remove '%s'", cpu_cgroup_path);
	if (rmdir(cpu_cgroup_path) == -1) {
		PLOG_W("rmdir('%s') failed", cpu_cgroup_path);
	}
	return;
}

void finishFromParentNetCls(struct nsjconf_t* nsjconf, pid_t pid) {
	if (nsjconf->cgroup_net_cls_classid == 0U) {
		return;
	}
	char net_cls_cgroup_path[PATH_MAX];
	snprintf(net_cls_cgroup_path, sizeof(net_cls_cgroup_path), "%s/%s/NSJAIL.%d",
	    nsjconf->cgroup_net_cls_mount, nsjconf->cgroup_net_cls_parent, (int)pid);
	LOG_D("Remove '%s'", net_cls_cgroup_path);
	if (rmdir(net_cls_cgroup_path) == -1) {
		PLOG_W("rmdir('%s') failed", net_cls_cgroup_path);
	}
	return;
}

void finishFromParent(struct nsjconf_t* nsjconf, pid_t pid) {
	finishFromParentMem(nsjconf, pid);
	finishFromParentPids(nsjconf, pid);
	finishFromParentNetCls(nsjconf, pid);
	finishFromParentCpu(nsjconf, pid);
}

bool initNs(void) { return true; }

}  // namespace cgroup
