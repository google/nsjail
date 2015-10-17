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
#ifndef _LOG_H
#define _LOG_H

#include <getopt.h>
#include <stdbool.h>

#include "common.h"

#define LOG_HELP(...) logLog(HELP, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_HELP_BOLD(...) logLog(HELP_BOLD, __func__, __LINE__, false, __VA_ARGS__);

#define LOG_D(...) logLog(DEBUG, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_I(...) logLog(INFO, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_W(...) logLog(WARNING, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_E(...) logLog(ERROR, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_F(...) logLog(FATAL, __func__, __LINE__, false, __VA_ARGS__);

#define PLOG_D(...) logLog(DEBUG, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_I(...) logLog(INFO, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_W(...) logLog(WARNING, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_E(...) logLog(ERROR, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_F(...) logLog(FATAL, __func__, __LINE__, true, __VA_ARGS__);

enum llevel_t {
	HELP = 0,
	HELP_BOLD,
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	FATAL
};

bool logInitLogFile(struct nsjconf_t *nsjconf, const char *logfile, bool is_verbose);
void logLog(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
    __attribute__ ((format(printf, 5, 6)));
void logStop(int sig);
void logRedirectLogFD(int fd);
void logDirectlyToFD(const char *msg);

#endif				/* _LOG_H */
