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
#include <stdint.h>
#include <stdlib.h>

#include "nsjail.h"

void* utilMalloc(size_t sz);
void* utilCalloc(size_t sz);
char* utilStrDup(const char* str);
uint8_t* utilMemDup(const uint8_t* src, size_t len);
ssize_t utilReadFromFd(int fd, void* buf, size_t len);
ssize_t utilReadFromFile(const char* fname, void* buf, size_t len);
ssize_t utilWriteToFd(int fd, const void* buf, size_t len);
bool utilWriteBufToFile(const char* filename, const void* buf, size_t len, int open_flags);
bool utilCreateDirRecursively(const char* dir);
int utilSSnPrintf(char* str, size_t size, const char* format, ...);
bool utilIsANumber(const char* s);
uint64_t utilRnd64(void);
const char* utilSigName(int signo);
const char* utilTimeToStr(time_t t);

#endif /* NS_UTIL_H */
