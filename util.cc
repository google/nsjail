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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "missing_defs.h"

namespace util {

ssize_t readFromFd(int fd, void* buf, size_t len) {
	uint8_t* charbuf = (uint8_t*)buf;

	size_t readSz = 0;
	while (readSz < len) {
		ssize_t sz = TEMP_FAILURE_RETRY(read(fd, &charbuf[readSz], len - readSz));
		if (sz < 0) {
			return readSz > 0 ? (ssize_t)readSz : -1;
		}
		if (sz == 0) {
			break;
		}
		readSz += sz;
	}
	return readSz;
}

ssize_t readFromFile(const char* fname, void* buf, size_t len) {
	int fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		LOG_E("open(%s, O_RDONLY|O_CLOEXEC)", QC(fname));
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
		if (sz <= 0) {
			return false;
		}
		writtenSz += sz;
	}
	return true;
}

bool sendMsg(int sock, uint32_t msg_val, int fd) {
	struct msghdr msg = {};
	struct iovec io = {
	    .iov_base = &msg_val,
	    .iov_len = sizeof(msg_val),
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;

	char buf[CMSG_SPACE(sizeof(fd))] = {};
	if (fd >= 0) {
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		*((int*)CMSG_DATA(cmsg)) = fd;

		msg.msg_controllen = cmsg->cmsg_len;
	}

	return (TEMP_FAILURE_RETRY(sendmsg(sock, &msg, 0)) == sizeof(msg_val));
}

bool recvMsg(int sock, uint32_t* msg_val, int* fd) {
	struct msghdr msg = {};
	uint32_t local_msg = 0;
	struct iovec io = {
	    .iov_base = &local_msg,
	    .iov_len = sizeof(local_msg),
	};
	char c_buffer[256] = {};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = c_buffer;
	msg.msg_controllen = sizeof(c_buffer);

	ssize_t ret = TEMP_FAILURE_RETRY(recvmsg(sock, &msg, 0));
	if (ret < 0 || (size_t)ret != sizeof(local_msg)) {
		return false;
	}

	if (msg_val) {
		*msg_val = local_msg;
	}
	if (fd) {
		*fd = -1;
	}

	for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			size_t num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			int* fds = (int*)CMSG_DATA(cmsg);
			for (size_t i = 0; i < num_fds; ++i) {
				if (fd && *fd == -1) {
					*fd = fds[i];
				} else {
					close(fds[i]);
				}
			}
		}
	}
	return true;
}

bool sendFd(int sock, int fd) {
	return sendMsg(sock, 0, fd);
}

int recvFd(int sock) {
	int fd = -1;
	if (recvMsg(sock, nullptr, &fd)) {
		return fd;
	}
	return -1;
}

bool readFromFileToStr(const char* fname, std::string* str) {
	int fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		PLOG_W("Couldn't open file %s", QC(fname));
		return false;
	}
	defer {
		close(fd);
	};

	str->clear();
	char buf[4096];
	for (;;) {
		ssize_t sz = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf)));
		if (sz < 0) {
			PLOG_W("Reading from %s failed", QC(fname));
			return false;
		}
		if (sz == 0) {
			break;
		}
		str->append(buf, sz);
	}
	return true;
}

bool writeBufToFile(
    const char* filename, const void* buf, size_t len, int open_flags, bool log_errors) {
	int fd;
	TEMP_FAILURE_RETRY(fd = open(filename, open_flags | O_CLOEXEC, 0644));
	if (fd == -1) {
		if (log_errors) {
			PLOG_E("Couldn't open %s for writing", QC(filename));
		}
		return false;
	}

	if (!writeToFd(fd, buf, len)) {
		if (log_errors) {
			PLOG_E("Couldn't write '%zu' bytes to file %s (fd='%d')", len, QC(filename),
			    fd);
		}
		close(fd);
		if (open_flags & O_CREAT) {
			unlink(filename);
		}
		return false;
	}

	LOG_D("Written '%zu' bytes to %s", len, QC(filename));

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
	if (snprintf(path, sizeof(path), "%s", dir) >= (int)sizeof(path)) {
		LOG_W("Directory path is too long: '%s'", dir);
		close(prev_dir_fd);
		return false;
	}
	char* curr = path;
	for (;;) {
		while (*curr == '/') {
			curr++;
		}

		char* next = strchr(curr, '/');
		if (next == nullptr) {
			close(prev_dir_fd);
			return true;
		}
		*next = '\0';

		if (mkdirat(prev_dir_fd, curr, 0755) == -1 && errno != EEXIST) {
			if (errno != EROFS || !util::existsAsDirAt(prev_dir_fd, curr)) {
				PLOG_W("mkdir(%s, 0755)", QC(curr));
				close(prev_dir_fd);
				return false;
			}
		}

		int dir_fd = TEMP_FAILURE_RETRY(openat(prev_dir_fd, curr, O_DIRECTORY | O_CLOEXEC));
		if (dir_fd == -1) {
			PLOG_W("openat('%d', %s, O_DIRECTORY | O_CLOEXEC)", prev_dir_fd, QC(curr));
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

const std::string StrQuote(const std::string& str) {
	std::ostringstream ss;
	ss << std::quoted(str, '\'');
	return ss.str();
}

bool isANumber(const char* s) {
	for (; *s; s++) {
		if (!isdigit(*s) && *s != 'x') {
			return false;
		}
	}
	return true;
}

bool StrEq(const std::string_view& s1, const std::string_view& s2) {
	return (s1 == s2);
}

static __thread pthread_once_t rndThreadOnce = PTHREAD_ONCE_INIT;
static __thread uint64_t rndX;

/* MMIX LCG PRNG */
static const uint64_t a = 6364136223846793005ULL;
static const uint64_t c = 1442695040888963407ULL;

static void rndInitThread(void) {
	if (TEMP_FAILURE_RETRY(util::syscall(__NR_getrandom, (uintptr_t)&rndX, sizeof(rndX), 0)) ==
	    sizeof(rndX)) {
		return;
	}
	int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		PLOG_D("Couldn't open /dev/urandom for reading. Using gettimeofday "
		       "fall-back");
		struct timeval tv;
		gettimeofday(&tv, NULL);
		rndX = tv.tv_usec + ((uint64_t)tv.tv_sec << 32);
		return;
	}
	if (readFromFd(fd, (uint8_t*)&rndX, sizeof(rndX)) != sizeof(rndX)) {
		PLOG_F("Couldn't read '%zu' bytes from /dev/urandom", sizeof(rndX));
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
	    NS_VALSTR_STRUCT(SIGHUP),
	    NS_VALSTR_STRUCT(SIGINT),
	    NS_VALSTR_STRUCT(SIGQUIT),
	    NS_VALSTR_STRUCT(SIGILL),
	    NS_VALSTR_STRUCT(SIGTRAP),
	    NS_VALSTR_STRUCT(SIGABRT),
	    NS_VALSTR_STRUCT(SIGIOT),
	    NS_VALSTR_STRUCT(SIGBUS),
	    NS_VALSTR_STRUCT(SIGFPE),
	    NS_VALSTR_STRUCT(SIGKILL),
	    NS_VALSTR_STRUCT(SIGUSR1),
	    NS_VALSTR_STRUCT(SIGSEGV),
	    NS_VALSTR_STRUCT(SIGUSR2),
	    NS_VALSTR_STRUCT(SIGPIPE),
	    NS_VALSTR_STRUCT(SIGALRM),
	    NS_VALSTR_STRUCT(SIGTERM),
	    NS_VALSTR_STRUCT(SIGSTKFLT),
	    NS_VALSTR_STRUCT(SIGCHLD),
	    NS_VALSTR_STRUCT(SIGCONT),
	    NS_VALSTR_STRUCT(SIGSTOP),
	    NS_VALSTR_STRUCT(SIGTSTP),
	    NS_VALSTR_STRUCT(SIGTTIN),
	    NS_VALSTR_STRUCT(SIGTTOU),
	    NS_VALSTR_STRUCT(SIGURG),
	    NS_VALSTR_STRUCT(SIGXCPU),
	    NS_VALSTR_STRUCT(SIGXFSZ),
	    NS_VALSTR_STRUCT(SIGVTALRM),
	    NS_VALSTR_STRUCT(SIGPROF),
	    NS_VALSTR_STRUCT(SIGWINCH),
	    NS_VALSTR_STRUCT(SIGPOLL),
	    NS_VALSTR_STRUCT(SIGPWR),
	    NS_VALSTR_STRUCT(SIGSYS),
	};

	for (const auto& i : sigNames) {
		if (signo == i.signo) {
			res.append(i.name);
			return res;
		}
	}

	if (signo >= SIGRTMIN) {
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

const std::string rLimName(int res) {
	std::string ret;

	struct {
		const int res;
		const char* const name;
	} static const rLimNames[] = {
	    NS_VALSTR_STRUCT(RLIMIT_CPU),
	    NS_VALSTR_STRUCT(RLIMIT_FSIZE),
	    NS_VALSTR_STRUCT(RLIMIT_DATA),
	    NS_VALSTR_STRUCT(RLIMIT_STACK),
	    NS_VALSTR_STRUCT(RLIMIT_CORE),
	    NS_VALSTR_STRUCT(RLIMIT_RSS),
	    NS_VALSTR_STRUCT(RLIMIT_NOFILE),
	    NS_VALSTR_STRUCT(RLIMIT_AS),
	    NS_VALSTR_STRUCT(RLIMIT_NPROC),
	    NS_VALSTR_STRUCT(RLIMIT_MEMLOCK),
	    NS_VALSTR_STRUCT(RLIMIT_LOCKS),
	    NS_VALSTR_STRUCT(RLIMIT_SIGPENDING),
	    NS_VALSTR_STRUCT(RLIMIT_MSGQUEUE),
	    NS_VALSTR_STRUCT(RLIMIT_NICE),
	    NS_VALSTR_STRUCT(RLIMIT_RTPRIO),
	    NS_VALSTR_STRUCT(RLIMIT_RTTIME),
	};

	for (const auto& i : rLimNames) {
		if (res == i.res) {
			ret.append(i.name);
			return ret;
		}
	}

	ret.append("RLIMITUNKNOWN(");
	ret.append(std::to_string(res));
	ret.append(")");
	return ret;
}

uint64_t timeUsec(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
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

long setrlimit(int res, const struct rlimit64& newlim) {
	return util::syscall(__NR_prlimit64, 0, res, (uintptr_t)&newlim, (uintptr_t)nullptr);
}

long getrlimit(int res, struct rlimit64* curlim) {
	*curlim = {};
	return util::syscall(__NR_prlimit64, 0, res, (uintptr_t)nullptr, (uintptr_t)curlim);
}

bool makeRangeCOE(unsigned int first, unsigned int last) {
	if (util::syscall(__NR_close_range, first, last, CLOSE_RANGE_CLOEXEC) == -1) {
		if (errno != ENOSYS) {
			PLOG_E("close_range(first=%u, last=%u, CLOSE_RANGE_CLOEXEC)", first, last);
		}
		return false;
	}
	return true;
}

const char* stripLeadingSlashes(const char* path) {
	while (*path == '/') {
		path++;
	}
	return path;
}

bool kernelVersionAtLeast(int major, int minor, int patch) {
	struct utsname uts;
	if (uname(&uts) == -1) {
		PLOG_W("uname()");
		return false;
	}

	int kmajor = 0, kminor = 0, kpatch = 0;
	if (sscanf(uts.release, "%d.%d.%d", &kmajor, &kminor, &kpatch) < 2) {
		LOG_W("Couldn't parse kernel version from '%s'", uts.release);
		return false;
	}

	if (kmajor != major) {
		return kmajor > major;
	}
	if (kminor != minor) {
		return kminor > minor;
	}
	return kpatch >= patch;
}

void detachFromTTY(void) {
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd == -1) {
		LOG_D("Could not open /dev/tty (expected if no controlling terminal)");
		return;
	}
	defer {
		close(fd);
	};
	if (ioctl(fd, TIOCNOTTY) == -1) {
		PLOG_W("ioctl(TIOCNOTTY) failed");
		return;
	}
	LOG_D("Successfully detached from controlling terminal via TIOCNOTTY");
}

bool setNonBlock(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl == -1 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
		PLOG_W("fcntl(fd=%d, O_NONBLOCK)", fd);
		return false;
	}
	return true;
}

}  // namespace util
