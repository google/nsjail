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

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "nsjail.h"

#define RETURN_ON_FAILURE(expr)       \
	do {                          \
		if (!(expr)) {        \
			return false; \
		}                     \
	} while (0)

namespace util {

ssize_t readFromFd(int fd, void* buf, size_t len);
ssize_t readFromFile(const char* fname, void* buf, size_t len);
bool writeToFd(int fd, const void* buf, size_t len);
bool writeBufToFile(const char* filename, const void* buf, size_t len, int open_flags);
bool createDirRecursively(const char* dir);
std::string* StrAppend(std::string* str, const char* format, ...)
    __attribute__((format(printf, 2, 3)));
std::string StrPrintf(const char* format, ...) __attribute__((format(printf, 1, 2)));
bool isANumber(const char* s);
uint64_t rnd64(void);
const std::string sigName(int signo);
const std::string timeToStr(time_t t);
std::vector<std::string> strSplit(const std::string str, char delim);
long syscall(long sysno, uintptr_t a0 = 0, uintptr_t a1 = 0, uintptr_t a2 = 0, uintptr_t a3 = 0,
    uintptr_t a4 = 0, uintptr_t a5 = 0);

}  // namespace util

#endif /* NS_UTIL_H */
