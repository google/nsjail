/*

   nsjail - logging
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

#include "logs.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "macros.h"
#include "util.h"

namespace logs {

static int _log_fd = STDERR_FILENO;
static bool _log_fd_isatty = true;
static enum llevel_t _log_level = INFO;
static bool _log_set = false;
static enum llevel_t _log_stderr_level = FATAL;
static int _log_stderr_fd = -1;
static bool _log_stderr_fd_isatty = false;
static bool _log_stderr_fd_distinct = false;

static bool fdIsatty(int fd) {
	int saved_errno = errno;
	bool ret = (isatty(fd) == 1) && !getenv("NO_COLOR");
	errno = saved_errno;
	return ret;
}

static void setDupLogFdOr(int fd, int orfd) {
	int saved_errno = errno;
	_log_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (_log_fd == -1) {
		_log_fd = fcntl(orfd, F_DUPFD_CLOEXEC, 0);
	}
	if (_log_fd == -1) {
		_log_fd = orfd;
	}
	_log_fd_isatty = fdIsatty(_log_fd);
	errno = saved_errno;
}

static void updateStderrFdDistinct(void) {
	if (_log_stderr_fd == -1) {
		_log_stderr_fd_distinct = false;
		return;
	}
	struct stat st_log, st_err;
	if (fstat(_log_fd, &st_log) == -1 || fstat(_log_stderr_fd, &st_err) == -1) {
		_log_stderr_fd_distinct = true;
		PLOG_W("fstat(log_fd=%d, stderr_fd=%d) failed, treating them as separate",
		    _log_fd, _log_stderr_fd);
		return;
	}
	_log_stderr_fd_distinct =
	    (st_log.st_dev != st_err.st_dev || st_log.st_ino != st_err.st_ino);
}

/*
 * Log to stderr by default. Use a dup()d fd, because in the future we'll associate the
 * connection socket with fd (0, 1, 2).
 */
__attribute__((constructor)) static void log_init(void) {
	setDupLogFdOr(STDERR_FILENO, STDERR_FILENO);
}

bool logSet() {
	return _log_set;
}

int logFd() {
	return _log_fd;
}

void setLogLevel(enum llevel_t ll) {
	_log_level = ll;
}

enum llevel_t getLogLevel(void) {
	if (_log_stderr_fd >= 0 && _log_stderr_fd_distinct && _log_stderr_level < _log_level) {
		return _log_stderr_level;
	}
	return _log_level;
}

bool setLogStderrLevel(enum llevel_t ll) {
	_log_stderr_level = ll;
	if (_log_stderr_fd == -1) {
		_log_stderr_fd = TEMP_FAILURE_RETRY(fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 0));
		if (_log_stderr_fd == -1) {
			if (errno == EBADF) {
				PLOG_W("stderr is closed, log_stderr_level disabled");
				return true;
			}
			PLOG_E("Couldn't duplicate stderr");
			return false;
		}
		_log_stderr_fd_isatty = fdIsatty(_log_stderr_fd);
	}
	updateStderrFdDistinct();
	return true;
}

void closeLogStderr(void) {
	if (_log_stderr_fd == -1) {
		return;
	}
	LOG_W("Daemonized, log_stderr_level disabled");
	close(_log_stderr_fd);
	_log_stderr_fd = -1;
	_log_stderr_fd_distinct = false;
}

void logFile(const std::string& log_file, int log_fd) {
	_log_set = true;
	int newlogfd = -1;
	if (!log_file.empty()) {
		newlogfd = TEMP_FAILURE_RETRY(
		    open(log_file.c_str(), O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
			0640));
		if (newlogfd == -1) {
			PLOG_W("Couldn't open('%s')", log_file.c_str());
		}
	}
	/* Close previous log_fd */
	if (_log_fd > STDERR_FILENO) {
		close(_log_fd);
	}
	setDupLogFdOr(newlogfd, log_fd);
	if (newlogfd >= 0) {
		close(newlogfd);
	}
	updateStderrFdDistinct();
}

static bool isHelp(enum llevel_t ll) {
	return ll == HELP || ll == HELP_BOLD;
}

static void writeLogMsg(int fd, bool is_tty, const char* prefix, const std::string& msg) {
	std::string out;
	out.reserve(msg.size() + 16);
	if (is_tty) {
		out.append(prefix).append(msg).append("\033[0m");
	} else {
		out.append(msg);
	}
	out.append("\n");
	TEMP_FAILURE_RETRY(write(fd, out.c_str(), out.size()));
}

void logMsg(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...) {
	const bool to_main = ll >= _log_level;
	const bool to_stderr = _log_stderr_fd >= 0 && _log_stderr_fd_distinct &&
			       ll >= _log_stderr_level && !isHelp(ll);
	if (!to_main && !to_stderr) {
		return;
	}

	char strerr[512];
	if (perr) {
		snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
	}
	struct {
		const char* const descr;
		const char* const prefix;
		const bool print_funcline;
		const bool print_time;
	} static const logLevels[] = {
	    {"D", "\033[0;4m", true, true},
	    {"I", "\033[1m", false, true},
	    {"W", "\033[0;33m", true, true},
	    {"E", "\033[1;31m", true, true},
	    {"F", "\033[7;35m", true, true},
	    {"HR", "\033[0m", false, false},
	    {"HB", "\033[1m", false, false},
	};

	/* Start printing logs */
	std::string msg;
	if (!isHelp(ll)) {
		msg.append("[").append(logLevels[ll].descr).append("]");
	}
	if (logLevels[ll].print_time) {
		msg.append("[").append(util::timeToStr(time(NULL))).append("]");
	}

	int pid = getpid();
	int tid = gettid();
	if (logLevels[ll].print_funcline) {
		msg.append("[")
		    .append(std::to_string(pid))
		    .append(pid == tid ? "" : ("/" + std::to_string(tid)))
		    .append("] ")
		    .append(fn)
		    .append("():")
		    .append(std::to_string(ln));
	}

	char* strp;
	va_list args;
	va_start(args, fmt);
	int ret = vasprintf(&strp, fmt, args);
	va_end(args);
	if (ret == -1) {
		msg.append(" [logs internal]: MEMORY ALLOCATION ERROR");
	} else {
		msg.append(" ").append(strp);
		free(strp);
	}
	if (perr) {
		msg.append(": ").append(strerr);
	}
	/* End printing logs */

	if (to_main) {
		writeLogMsg(_log_fd, _log_fd_isatty, logLevels[ll].prefix, msg);
	}
	if (to_stderr) {
		writeLogMsg(_log_stderr_fd, _log_stderr_fd_isatty, logLevels[ll].prefix, msg);
	}

	if (ll == FATAL) {
		_exit(0xff);
	}
}

void logStop(int sig) {
	LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig);
}

}  // namespace logs
