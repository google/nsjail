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
#include "log.h"

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

static int log_fd = STDERR_FILENO;
static bool log_fd_isatty = true;
static enum llevel_t log_level = INFO;

#define _LOG_DEFAULT_FILE "/var/log/nsjail.log"

/*
 * Log to stderr by default. Use a dup()d fd, because in the future we'll associate the
 * connection socket with fd (0, 1, 2).
 */
bool logInitLogFile(struct nsjconf_t* nsjconf)
{
	/* Close previous log_fd */
	if (log_fd > STDERR_FILENO) {
		close(log_fd);
		log_fd = STDERR_FILENO;
	}
	log_fd = nsjconf->log_fd;
	log_level = nsjconf->loglevel;

	if (nsjconf->logfile == NULL && nsjconf->daemonize == true) {
		nsjconf->logfile = _LOG_DEFAULT_FILE;
	}
	if (nsjconf->logfile == NULL) {
		log_fd = fcntl(log_fd, F_DUPFD_CLOEXEC, 0);
	} else {
		if (TEMP_FAILURE_RETRY(
			log_fd = open(nsjconf->logfile, O_CREAT | O_RDWR | O_APPEND, 0640))
		    == -1) {
			log_fd = STDERR_FILENO;
			PLOG_E("Couldn't open logfile open('%s')", nsjconf->logfile);
			return false;
		}
	}
	log_fd_isatty = (isatty(log_fd) == 1 ? true : false);
	return true;
}

void logLog(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...)
{
	if (ll < log_level) {
		return;
	}

	char strerr[512];
	if (perr == true) {
		snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
	}
	struct ll_t {
		const char* const descr;
		const char* const prefix;
		const bool print_funcline;
		const bool print_time;
	};
	static struct ll_t const logLevels[] = {
		{ "D", "\033[0;4m", true, true },
		{ "I", "\033[1m", false, true },
		{ "W", "\033[0;33m", true, true },
		{ "E", "\033[1;31m", true, true },
		{ "F", "\033[7;35m", true, true },
		{ "HR", "\033[0m", false, false },
		{ "HB", "\033[1m", false, false },
	};

	time_t ltstamp = time(NULL);
	struct tm utctime;
	localtime_r(&ltstamp, &utctime);
	char timestr[32];
	if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
		timestr[0] = '\0';
	}

	/* Start printing logs */
	if (log_fd_isatty) {
		dprintf(log_fd, "%s", logLevels[ll].prefix);
	}
	if (logLevels[ll].print_time) {
		dprintf(log_fd, "[%s] ", timestr);
	}
	if (logLevels[ll].print_funcline) {
		dprintf(log_fd, "[%s][%d] %s():%d ", logLevels[ll].descr, (int)getpid(), fn, ln);
	}

	va_list args;
	va_start(args, fmt);
	vdprintf(log_fd, fmt, args);
	va_end(args);
	if (perr == true) {
		dprintf(log_fd, ": %s", strerr);
	}
	if (log_fd_isatty) {
		dprintf(log_fd, "\033[0m");
	}
	dprintf(log_fd, "\n");
	/* End printing logs */

	if (ll == FATAL) {
		exit(0xff);
	}
}

void logStop(int sig) { LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig); }
