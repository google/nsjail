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

static bool userUidGidMap(struct nsjconf_t *nsjconf, pid_t pid)
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
