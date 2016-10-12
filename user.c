/*

   nsjail - CLONE_NEWUSER routines
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

#include "user.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "subproc.h"
#include "util.h"

static bool userSetGroups(pid_t pid)
{
	/*
	 * No need to write 'deny' to /proc/pid/setgroups if our euid==0, as writing to uid_map/gid_map
	 * will succeed anyway
	 */
	if (geteuid() == 0) {
		return true;
	}

	char fname[PATH_MAX];
	snprintf(fname, sizeof(fname), "/proc/%d/setgroups", pid);
	const char *denystr = "deny";
	if (utilWriteBufToFile(fname, denystr, strlen(denystr), O_WRONLY) == false) {
		LOG_E("utilWriteBufToFile('%s', '%s') failed", fname, denystr);
		return false;
	}
	return true;
}

static bool userUidMapSelf(struct nsjconf_t *nsjconf, pid_t pid)
{
	char fname[PATH_MAX];
	char map[128];

	snprintf(fname, sizeof(fname), "/proc/%d/uid_map", pid);
	snprintf(map, sizeof(map), "%lu %lu 1", (unsigned long)nsjconf->inside_uid,
		 (unsigned long)nsjconf->outside_uid);
	LOG_D("Writing '%s' to '%s'", map, fname);
	if (utilWriteBufToFile(fname, map, strlen(map), O_WRONLY) == false) {
		LOG_E("utilWriteBufToFile('%s', '%s') failed", fname, map);
		return false;
	}

	return true;
}

static bool userGidMapSelf(struct nsjconf_t *nsjconf, pid_t pid)
{
	char fname[PATH_MAX];
	char map[128];

	snprintf(fname, sizeof(fname), "/proc/%d/gid_map", pid);
	snprintf(map, sizeof(map), "%lu %lu 1", (unsigned long)nsjconf->inside_gid,
		 (unsigned long)nsjconf->outside_gid);
	LOG_D("Writing '%s' to '%s'", map, fname);
	if (utilWriteBufToFile(fname, map, strlen(map), O_WRONLY) == false) {
		LOG_E("utilWriteBufToFile('%s', '%s') failed", fname, map);
		return false;
	}
	return true;
}

/* Use /usr/bin/newgidmap for writing the gid map */
static bool userGidMapExternal(struct nsjconf_t *nsjconf, pid_t pid)
{
	char pid_str[16];
	char ins_gid_str[16];
	char out_gid_str[16];

	snprintf(pid_str, sizeof(pid_str), "%lu", (unsigned long)pid);
	snprintf(ins_gid_str, sizeof(ins_gid_str), "%lu", (unsigned long)nsjconf->inside_gid);
	snprintf(out_gid_str, sizeof(out_gid_str), "%lu", (unsigned long)nsjconf->outside_gid);

	const char *argv[1024] = { "/usr/bin/newgidmap", pid_str, ins_gid_str, out_gid_str, "1" };
	size_t argv_idx = 5;

	struct mapping_t *p;
	TAILQ_FOREACH(p, &nsjconf->gid_mappings, pointers) {
		if ((argv_idx + 4) >= ARRAYSIZE(argv)) {
			LOG_W("Number of arguments to '/usr/bin/newgidmap' too big");
			return false;
		}

		argv[argv_idx++] = p->inside_id;
		argv[argv_idx++] = p->outside_id;
		argv[argv_idx++] = p->count;
	}
	argv[argv_idx++] = NULL;

	if (subprocSystem(argv, environ) != 0) {
		LOG_E("'/usr/bin/newgidmap' failed");
		return false;
	}

	return true;
}

/* Use /usr/bin/newuidmap for writing the uid map */
static bool userUidMapExternal(struct nsjconf_t *nsjconf, pid_t pid)
{
	char pid_str[16];
	char ins_uid_str[16];
	char out_uid_str[16];

	snprintf(pid_str, sizeof(pid_str), "%lu", (unsigned long)pid);
	snprintf(ins_uid_str, sizeof(ins_uid_str), "%lu", (unsigned long)nsjconf->inside_uid);
	snprintf(out_uid_str, sizeof(out_uid_str), "%lu", (unsigned long)nsjconf->outside_uid);

	const char *argv[1024] = { "/usr/bin/newuidmap", pid_str, ins_uid_str, out_uid_str, "1" };
	size_t argv_idx = 5;

	struct mapping_t *p;
	TAILQ_FOREACH(p, &nsjconf->uid_mappings, pointers) {
		if ((argv_idx + 4) >= ARRAYSIZE(argv)) {
			LOG_W("Number of arguments to '/usr/bin/newuidmap' too big");
			return false;
		}

		argv[argv_idx++] = p->inside_id;
		argv[argv_idx++] = p->outside_id;
		argv[argv_idx++] = p->count;
	}
	argv[argv_idx++] = NULL;

	if (subprocSystem(argv, environ) != 0) {
		LOG_E("'/usr/bin/newuidmap' failed");
		return false;
	}

	return true;
}

static bool userUidGidMap(struct nsjconf_t *nsjconf, pid_t pid)
{
	if (TAILQ_EMPTY(&nsjconf->gid_mappings)) {
		if (!userGidMapSelf(nsjconf, pid)) {
			return false;
		}
	} else {
		if (!userGidMapExternal(nsjconf, pid)) {
			return false;
		}
	}
	if (TAILQ_EMPTY(&nsjconf->uid_mappings)) {
		return userUidMapSelf(nsjconf, pid);
	} else {
		return userUidMapExternal(nsjconf, pid);
	}
}

bool userInitNsFromParent(struct nsjconf_t * nsjconf, pid_t pid)
{
	if (nsjconf->clone_newuser == false) {
		return true;
	}
	if (userSetGroups(pid) == false) {
		return false;
	}
	if (userUidGidMap(nsjconf, pid) == false) {
		return false;
	}
	return true;
}
