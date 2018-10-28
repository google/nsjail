/*

   nsjail - cmdline parsing
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

#ifndef NS_CMDLINE_H
#define NS_CMDLINE_H

#include <stdint.h>

#include <memory>
#include <string>

#include "nsjail.h"

namespace cmdline {

uint64_t parseRLimit(int res, const char* optarg, unsigned long mul);
void logParams(nsjconf_t* nsjconf);
void addEnv(nsjconf_t* nsjconf, const std::string& env);
std::unique_ptr<nsjconf_t> parseArgs(int argc, char* argv[]);

}  // namespace cmdline

#endif /* _CMDLINE_H */
