/*

   nsjail - config parsing
   -----------------------------------------

   Copyright 2017 Google Inc. All Rights Reserved.

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

#include "common.h"
#include "config.h"
#include "log.h"
#include "util.h"

#if !defined(NSJAIL_WITH_PROTOBUFC)
bool configParse(struct nsjconf_t * nsjconf UNUSED, const char *file UNUSED)
{
	LOG_W("nsjail was not compiled with the protobuf-c library");
	return false;
}
#else				/* !defined(NSJAIL_WITH_PROTOBUFC) */

#include "config.pb-c.h"

static bool configParseInternal(struct nsjconf_t *nsjconf, Nsjail__NsJailConfig * njc)
{
	if (njc->has_chroot) {
		nsjconf->chroot = utilStrDupLen((char *)njc->chroot.data, njc->chroot.len);
	}

	return true;
}

bool configParse(struct nsjconf_t * nsjconf, const char *file)
{
	uint8_t msg[1024 * 1024];

	ssize_t rsz = utilReadFromFile(file, msg, sizeof(msg));
	if (rsz < 0) {
		return false;
	}
	if (rsz == 0) {
		return false;
	}
	if (rsz == sizeof(msg)) {
		LOG_W("Config file '%s' too big (>= %zu bytes)", file, sizeof(msg));
		return false;
	}

	Nsjail__NsJailConfig *njc = nsjail__ns_jail_config__unpack(NULL, rsz, msg);
	if (njc == NULL) {
		LOG_E("Couldn't parse the config file");
		return false;
	}

	bool ret = configParseInternal(nsjconf, njc);
	nsjail__ns_jail_config__free_unpacked(njc, NULL);
	return ret;
}
#endif				/* !defined(NSJAIL_WITH_PROTOBUFC) */
