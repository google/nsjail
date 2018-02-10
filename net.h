/*

   nsjail - networking routines
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

#ifndef NS_NET_H
#define NS_NET_H

#include <stdbool.h>
#include <stddef.h>

#include <string>

#include "nsjail.h"

namespace net {

bool limitConns(nsjconf_t* nsjconf, int connsock);
int getRecvSocket(const char* bindhost, int port);
int acceptConn(int listenfd);
const std::string connToText(int fd, bool remote, struct sockaddr_in6* addr_or_null);
bool initNsFromParent(nsjconf_t* nsjconf, int pid);
bool initNsFromChild(nsjconf_t* nsjconf);

}  // namespace net

#endif /* _NET_H */
