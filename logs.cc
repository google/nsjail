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

static void setDupLogFdOr(int fd, int orfd) {
	int saved_errno = errno;
	_log_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (_log_fd == -1) {
		_log_fd = fcntl(orfd, F_DUPFD_CLOEXEC, 0);
	}
	if (_log_fd == -1) {
		_log_fd = orfd;
	}
	_log_fd_isatty = (isatty(_log_fd) == 1);
	errno = saved_errno;
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

void logLevel(enum llevel_t ll) {
	_log_level = ll;
}

void logFile(const std::string& log_file, int log_fd) {
	_log_set = true;
	int newlogfd = -1;
	if (!log_file.empty()) {
		newlogfd = TEMP_FAILURE_RETRY(
		    open(log_file.c_str(), O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC, 0640));
		if (newlogfd == -1) {
			PLOG_W("Couldn't open('%s')", log_file.c_str());
		}
	}
	/* Close previous log_fd */
	if (_log_fd > STDERR_FILENO) {
		close(_log_fd);
	}
	setDupLogFdOr(newlogfd, log_fd);
	close(newlogfd);
}

void logMsg(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...) {
	if (ll < _log_level) {
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
	if (_log_fd_isatty) {
		msg.append(logLevels[ll].prefix);
	}
	if (ll != HELP && ll != HELP_BOLD) {
		msg.append("[").append(logLevels[ll].descr).append("]");
	}
	if (logLevels[ll].print_time) {
		msg.append("[").append(util::timeToStr(time(NULL))).append("]");
	}
	if (logLevels[ll].print_funcline) {
		msg.append("[")
		    .append(std::to_string(getpid()))
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
	if (_log_fd_isatty) {
		msg.append("\033[0m");
	}
	msg.append("\n");
	/* End printing logs */

	TEMP_FAILURE_RETRY(write(_log_fd, msg.c_str(), msg.size()));

	if (ll == FATAL) {
		exit(0xff);
	}
}

void logStop(int sig) {
	LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig);
}

}  // namespace logs
