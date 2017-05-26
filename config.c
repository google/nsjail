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

#include <stdio.h>

#if !defined(NSJAIL_WITH_PROTOBUF)
bool configParse(struct nsjconf_t * nsjconf UNUSED, const char *file UNUSED)
{
	LOG_W("nsjail was not compiled with the protobuf-c library");
	return false;
}
#else				/* !defined(NSJAIL_WITH_PROTOBUF) */

#include "config.pb-c.h"
#include "protobuf-c-text.h"

static bool configParseInternal(struct nsjconf_t *nsjconf, Nsjail__NsJailConfig * njc)
{
	if (njc->has_mode) {
		switch (njc->mode) {
		case NSJAIL__MODE__LISTEN:
			nsjconf->mode = MODE_LISTEN_TCP;
			break;
		case NSJAIL__MODE__ONCE:
			nsjconf->mode = MODE_STANDALONE_ONCE;
			break;
		case NSJAIL__MODE__RERUN:
			nsjconf->mode = MODE_STANDALONE_RERUN;
			break;
		case NSJAIL__MODE__EXECVE:
			nsjconf->mode = MODE_STANDALONE_EXECVE;
			break;
		default:
			LOG_E("Uknown running mode: %d", njc->mode);
			return false;
		}
	}

	if (njc->has_chroot) {
		nsjconf->chroot = utilStrDupLen((char *)njc->chroot.data, njc->chroot.len);
	}

	return true;
}

bool configParse(struct nsjconf_t * nsjconf, const char *file)
{
	FILE *f = fopen(file, "rb");
	if (f == NULL) {
		PLOG_W("Couldn't open '%s' for reading", file);
		return false;
	}

	ProtobufCTextError error;
	Nsjail__NsJailConfig *njc =
	    (Nsjail__NsJailConfig *) protobuf_c_text_from_file(&nsjail__ns_jail_config__descriptor,
							       f, &error, NULL);
	if (njc == NULL) {
		LOG_W("Couldn't parse config from '%s': %s", file, error.error_txt);
		fclose(f);
		return false;
	}

	bool ret = configParseInternal(nsjconf, njc);
	fclose(f);
	return ret;
}
#endif				/* !defined(NSJAIL_WITH_PROTOBUF) */
