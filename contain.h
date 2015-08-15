/*

   nsjail - isolating the binary
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

#ifndef _CONTAIN_H
#define _CONTAIN_H

#include <stdbool.h>

#include "common.h"

bool containInitUserNs(struct nsjconf_t *nsjconf);
bool containDropPrivs(struct nsjconf_t *nsjconf);
bool containPrepareEnv(struct nsjconf_t *nsjconf);
bool containMountFS(struct nsjconf_t *nsjconf);
bool containSetLimits(struct nsjconf_t *nsjconf);
bool containMakeFdsCOE(void);
bool containSetupFD(struct nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err, int fd_log);

#endif				/* _CONTAIN_H */
