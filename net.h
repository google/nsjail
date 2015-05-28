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
#ifndef _NET_H
#define _NET_H

#include <stdbool.h>
#include <stddef.h>

#include "common.h"

bool netCloneMacVtapAndNS(struct nsjconf_t *nsjconf, int pid);
bool netLimitConns(struct nsjconf_t *nsjconf, int connsock);
int netGetRecvSocket(int port);
int netAcceptConn(int listenfd);
void netConnToText(int fd, bool remote, char *buf, size_t s, struct sockaddr_in6 *addr_or_null);

#endif				/* _NET_H */
