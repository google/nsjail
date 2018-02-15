/*

   nsjail - CLONE_NEWUTS routines
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

#include "uts.h"

#include <string.h>
#include <unistd.h>

#include "logs.h"

namespace uts {

bool initNs(nsjconf_t* nsjconf) {
	if (!nsjconf->clone_newuts) {
		return true;
	}

	LOG_D("Setting hostname to '%s'", nsjconf->hostname.c_str());
	if (sethostname(nsjconf->hostname.data(), nsjconf->hostname.length()) == -1) {
		PLOG_E("sethostname('%s')", nsjconf->hostname.c_str());
		return false;
	}
	return true;
}

}  // namespace uts
