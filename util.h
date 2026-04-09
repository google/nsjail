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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <string>
#include <vector>

#include "nsjail.h"

#define RETURN_ON_FAILURE(expr)                                                                    \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			return false;                                                              \
		}                                                                                  \
	} while (0)

#define QC(x) (util::StrQuote(x).c_str())

namespace util {

ssize_t readFromFd(int fd, void* buf, size_t len);
ssize_t readFromFile(const char* fname, void* buf, size_t len);
bool readFromFileToStr(const char* fname, std::string* str);
bool writeToFd(int fd, const void* buf, size_t len);

bool sendMsg(int sock, uint32_t msg, int fd = -1);
bool recvMsg(int sock, uint32_t* msg, int* fd = nullptr);

bool sendFd(int sock, int fd);
int recvFd(int sock);

bool writeBufToFile(
    const char* filename, const void* buf, size_t len, int open_flags, bool log_errors = true);
bool createDirRecursively(const char* dir);
std::string* StrAppend(std::string* str, const char* format, ...)
    __attribute__((format(printf, 2, 3)));
std::string StrPrintf(const char* format, ...) __attribute__((format(printf, 1, 2)));
const std::string StrQuote(const std::string& str);
bool StrEq(const std::string_view& s1, const std::string_view& s2);
bool isANumber(const char* s);
uint64_t rnd64(void);
const std::string sigName(int signo);
const std::string rLimName(int res);
uint64_t timeUsec(void);
const std::string timeToStr(time_t t);
std::vector<std::string> strSplit(const std::string str, char delim);
long syscall(long sysno, uintptr_t a0 = 0, uintptr_t a1 = 0, uintptr_t a2 = 0, uintptr_t a3 = 0,
    uintptr_t a4 = 0, uintptr_t a5 = 0);
long setrlimit(int res, const struct rlimit64& newlim);
long getrlimit(int res, struct rlimit64* curlim);
bool makeRangeCOE(unsigned int first, unsigned int last);
const char* stripLeadingSlashes(const char* path);
bool kernelVersionAtLeast(int major, int minor, int patch);
void detachFromTTY(void);
bool setNonBlock(int fd);
bool setNoDelay(int fd);

/*
 * EROFS fallback helpers for read-only filesystems (e.g. NFS).
 *
 * On NFSv3/v4 with a cold dentry cache, mkdir()/open(O_CREAT) can return
 * EROFS instead of EEXIST for entries that already exist.  These helpers
 * verify the entry exists with the expected type, preserving the original
 * errno for accurate PLOG logging on failure.
 */
inline bool existsAsDir(const char* path) {
	int saved = errno;
	struct stat st;
	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		return true;
	}
	errno = saved;
	return false;
}

inline bool existsAsDirAt(int dir_fd, const char* path) {
	int saved = errno;
	struct stat st;
	if (fstatat(dir_fd, path, &st, 0) == 0 && S_ISDIR(st.st_mode)) {
		return true;
	}
	errno = saved;
	return false;
}

inline bool existsAsReg(const char* path) {
	int saved = errno;
	struct stat st;
	if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
		return true;
	}
	errno = saved;
	return false;
}

inline bool existsAsRegAt(int dir_fd, const char* path) {
	int saved = errno;
	struct stat st;
	if (fstatat(dir_fd, path, &st, 0) == 0 && S_ISREG(st.st_mode)) {
		return true;
	}
	errno = saved;
	return false;
}

}  // namespace util

#endif /* NS_UTIL_H */
