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

#ifndef NS_LOG_H
#define NS_LOG_H

#include <getopt.h>
#include <stdbool.h>

#include "nsjail.h"

#define LOG_HELP(...) log::logMsg(HELP, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_HELP_BOLD(...) log::logMsg(HELP_BOLD, __func__, __LINE__, false, __VA_ARGS__);

#define LOG_D(...) log::logMsg(DEBUG, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_I(...) log::logMsg(INFO, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_W(...) log::logMsg(WARNING, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_E(...) log::logMsg(ERROR, __func__, __LINE__, false, __VA_ARGS__);
#define LOG_F(...) log::logMsg(FATAL, __func__, __LINE__, false, __VA_ARGS__);

#define PLOG_D(...) log::logMsg(DEBUG, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_I(...) log::logMsg(INFO, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_W(...) log::logMsg(WARNING, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_E(...) log::logMsg(ERROR, __func__, __LINE__, true, __VA_ARGS__);
#define PLOG_F(...) log::logMsg(FATAL, __func__, __LINE__, true, __VA_ARGS__);

namespace log {

bool initLogFile(struct nsjconf_t* nsjconf);
void logMsg(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...)
    __attribute__((format(printf, 5, 6)));
void logStop(int sig);

}  // namespace log

#endif /* NS_LOG_H */
