/*

   nsjail - useful procedures
   -----------------------------------------

   Copyright 2016 Google Inc. All Rights Reserved.

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

#ifndef NS_UTIL_H
#define NS_UTIL_H

#include <stdbool.h>
#include <stdlib.h>

#include "common.h"

void *utilMalloc(size_t sz);
ssize_t utilReadFromFd(int fd, void *buf, size_t len);
ssize_t utilReadFromFile(const char *fname, void *buf, size_t len);
ssize_t utilWriteToFd(int fd, const void *buf, size_t len);
bool utilWriteBufToFile(const char *filename, const void *buf, size_t len, int open_flags);
bool utilCreateDirRecursively(const char *dir);

#endif				/* NS_UTIL_H */
