/*

   nsjail - subprocess management
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

#ifndef NS_PROC_H
#define NS_PROC_H

#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "nsjail.h"

namespace subproc {

bool runChild(nsjconf_t* nsjconf, int fd_in, int fd_out, int fd_err);
int countProc(nsjconf_t* nsjconf);
void displayProc(nsjconf_t* nsjconf);
void killAndReapAll(nsjconf_t* nsjconf);
/* Returns the exit code of the first failing subprocess, or 0 if none fail */
int reapProc(nsjconf_t* nsjconf);
int systemExe(const std::vector<std::string>& args, char** env);
pid_t cloneProc(uintptr_t flags);

}  // namespace subproc

#endif /* NS_PROC_H */
