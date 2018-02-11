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

#ifndef NS_USER_H
#define NS_USER_H

#include <stdbool.h>

#include <string>

#include "nsjail.h"

namespace user {

bool initNsFromParent(nsjconf_t* nsjconf, pid_t pid);
bool initNsFromChild(nsjconf_t* nsjconf);
bool parseId(nsjconf_t* nsjconf, const std::string& i_id, const std::string& o_id, size_t cnt,
    bool is_gid, bool is_newidmap);

}  // namespace user

#endif /* NS_USER_H */
