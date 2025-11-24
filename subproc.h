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

/* 0 - network connection limit reached, -1 - error */
pid_t runChild(nsj_t* nsj, int listen_fd, int fd_in, int fd_out, int fd_err);
int countProc(nsj_t* nsj);
void displayProc(nsj_t* nsj);
void killAndReapAll(nsj_t* nsj, int signal);
/* Returns the exit code of the first failing subprocess, or 0 if none fail */
int reapProc(nsj_t* nsj);
int systemExe(const std::vector<std::string>& args, char** env);
pid_t cloneProc(uint64_t flags, int exit_signal);

}  // namespace subproc

#endif /* NS_PROC_H */
