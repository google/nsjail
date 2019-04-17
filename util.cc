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

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"

namespace util {

ssize_t readFromFd(int fd, void* buf, size_t len) {
	uint8_t* charbuf = (uint8_t*)buf;

	size_t readSz = 0;
	while (readSz < len) {
		ssize_t sz = TEMP_FAILURE_RETRY(read(fd, &charbuf[readSz], len - readSz));
		if (sz <= 0) {
			break;
		}
		readSz += sz;
	}
	return readSz;
}

ssize_t readFromFile(const char* fname, void* buf, size_t len) {
	int fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		LOG_E("open('%s', O_RDONLY|O_CLOEXEC)", fname);
		return -1;
	}
	ssize_t ret = readFromFd(fd, buf, len);
	close(fd);
	return ret;
}

bool writeToFd(int fd, const void* buf, size_t len) {
	const uint8_t* charbuf = (const uint8_t*)buf;

	size_t writtenSz = 0;
	while (writtenSz < len) {
		ssize_t sz = TEMP_FAILURE_RETRY(write(fd, &charbuf[writtenSz], len - writtenSz));
		if (sz < 0) {
			return false;
		}
		writtenSz += sz;
	}
	return true;
}

bool writeBufToFile(const char* filename, const void* buf, size_t len, int open_flags) {
	int fd;
	TEMP_FAILURE_RETRY(fd = open(filename, open_flags, 0644));
	if (fd == -1) {
		PLOG_E("Couldn't open '%s' for writing", filename);
		return false;
	}

	if (!writeToFd(fd, buf, len)) {
		PLOG_E("Couldn't write '%zu' bytes to file '%s' (fd='%d')", len, filename, fd);
		close(fd);
		if (open_flags & O_CREAT) {
			unlink(filename);
		}
		return false;
	}

	LOG_D("Written '%zu' bytes to '%s'", len, filename);

	close(fd);
	return true;
}

bool createDirRecursively(const char* dir) {
	if (dir[0] != '/') {
		LOG_W("The directory path must start with '/': '%s' provided", dir);
		return false;
	}

	int prev_dir_fd = TEMP_FAILURE_RETRY(open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY));
	if (prev_dir_fd == -1) {
		PLOG_W("open('/', O_RDONLY | O_CLOEXEC)");
		return false;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s", dir);
	char* curr = path;
	for (;;) {
		while (*curr == '/') {
			curr++;
		}

		char* next = strchr(curr, '/');
		if (next == NULL) {
			close(prev_dir_fd);
			return true;
		}
		*next = '\0';

		if (mkdirat(prev_dir_fd, curr, 0755) == -1 && errno != EEXIST) {
			PLOG_W("mkdir('%s', 0755)", curr);
			close(prev_dir_fd);
			return false;
		}

		int dir_fd = TEMP_FAILURE_RETRY(openat(prev_dir_fd, curr, O_DIRECTORY | O_CLOEXEC));
		if (dir_fd == -1) {
			PLOG_W("openat('%d', '%s', O_DIRECTORY | O_CLOEXEC)", prev_dir_fd, curr);
			close(prev_dir_fd);
			return false;
		}
		close(prev_dir_fd);
		prev_dir_fd = dir_fd;
		curr = next + 1;
	}
}

std::string* StrAppend(std::string* str, const char* format, ...) {
	char* strp;

	va_list args;
	va_start(args, format);
	int ret = vasprintf(&strp, format, args);
	va_end(args);

	if (ret == -1) {
		PLOG_E("Memory allocation failed during asprintf()");
		str->append(" [ERROR: mem_allocation_failed] ");
		return str;
	}

	str->append(strp, ret);
	free(strp);
	return str;
}

std::string StrPrintf(const char* format, ...) {
	char* strp;

	va_list args;
	va_start(args, format);
	int ret = vasprintf(&strp, format, args);
	va_end(args);

	if (ret == -1) {
		PLOG_E("Memory allocation failed during asprintf()");
		return "[ERROR: mem_allocation_failed]";
	}

	std::string str(strp, ret);
	free(strp);
	return str;
}

bool isANumber(const char* s) {
	for (size_t i = 0; s[i]; s++) {
		if (!isdigit(s[i]) && s[i] != 'x') {
			return false;
		}
	}
	return true;
}

static __thread pthread_once_t rndThreadOnce = PTHREAD_ONCE_INIT;
static __thread uint64_t rndX;

/* MMIX LCG PRNG */
static const uint64_t a = 6364136223846793005ULL;
static const uint64_t c = 1442695040888963407ULL;

static void rndInitThread(void) {
#if defined(__NR_getrandom)
	if (util::syscall(__NR_getrandom, (uintptr_t)&rndX, sizeof(rndX), 0) == sizeof(rndX)) {
		return;
	}
#endif /* defined(__NR_getrandom) */
	int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		PLOG_D(
		    "Couldn't open /dev/urandom for reading. Using gettimeofday "
		    "fall-back");
		struct timeval tv;
		gettimeofday(&tv, NULL);
		rndX = tv.tv_usec + ((uint64_t)tv.tv_sec << 32);
		return;
	}
	if (readFromFd(fd, (uint8_t*)&rndX, sizeof(rndX)) != sizeof(rndX)) {
		PLOG_F("Couldn't read '%zu' bytes from /dev/urandom", sizeof(rndX));
		close(fd);
	}
	close(fd);
}

uint64_t rnd64(void) {
	pthread_once(&rndThreadOnce, rndInitThread);
	rndX = a * rndX + c;
	return rndX;
}

const std::string sigName(int signo) {
	std::string res;

	struct {
		const int signo;
		const char* const name;
	} static const sigNames[] = {
	    NS_VALSTR_STRUCT(SIGINT),
	    NS_VALSTR_STRUCT(SIGILL),
	    NS_VALSTR_STRUCT(SIGABRT),
	    NS_VALSTR_STRUCT(SIGFPE),
	    NS_VALSTR_STRUCT(SIGSEGV),
	    NS_VALSTR_STRUCT(SIGTERM),
	    NS_VALSTR_STRUCT(SIGHUP),
	    NS_VALSTR_STRUCT(SIGQUIT),
	    NS_VALSTR_STRUCT(SIGTRAP),
	    NS_VALSTR_STRUCT(SIGKILL),
	    NS_VALSTR_STRUCT(SIGBUS),
	    NS_VALSTR_STRUCT(SIGSYS),
	    NS_VALSTR_STRUCT(SIGPIPE),
	    NS_VALSTR_STRUCT(SIGALRM),
	    NS_VALSTR_STRUCT(SIGURG),
	    NS_VALSTR_STRUCT(SIGSTOP),
	    NS_VALSTR_STRUCT(SIGTSTP),
	    NS_VALSTR_STRUCT(SIGCONT),
	    NS_VALSTR_STRUCT(SIGCHLD),
	    NS_VALSTR_STRUCT(SIGTTIN),
	    NS_VALSTR_STRUCT(SIGTTOU),
	    NS_VALSTR_STRUCT(SIGPOLL),
	    NS_VALSTR_STRUCT(SIGXCPU),
	    NS_VALSTR_STRUCT(SIGXFSZ),
	    NS_VALSTR_STRUCT(SIGVTALRM),
	    NS_VALSTR_STRUCT(SIGPROF),
	    NS_VALSTR_STRUCT(SIGUSR1),
	    NS_VALSTR_STRUCT(SIGUSR2),
	    NS_VALSTR_STRUCT(SIGWINCH),
	};

	for (const auto& i : sigNames) {
		if (signo == i.signo) {
			res.append(i.name);
			return res;
		}
	}

	if (signo > SIGRTMIN) {
		res.append("SIG");
		res.append(std::to_string(signo));
		res.append("-RTMIN+");
		res.append(std::to_string(signo - SIGRTMIN));
		return res;
	}

	res.append("SIGUNKNOWN(");
	res.append(std::to_string(signo));
	res.append(")");
	return res;
}

const std::string timeToStr(time_t t) {
	char timestr[128];
	struct tm utctime;
	localtime_r(&t, &utctime);
	if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
		return "[Time conv error]";
	}
	return timestr;
}

std::vector<std::string> strSplit(const std::string str, char delim) {
	std::vector<std::string> vec;
	std::istringstream stream(str);
	for (std::string word; std::getline(stream, word, delim);) {
		vec.push_back(word);
	}
	return vec;
}

long syscall(long sysno, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5) {
	return ::syscall(sysno, a0, a1, a2, a3, a4, a5);
}

}  // namespace util
