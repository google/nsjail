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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"

void *utilMalloc(size_t sz)
{
	void *ret = malloc(sz);
	if (ret == NULL) {
		LOG_F("malloc(sz=%zu) failed", sz);
	}
	return ret;
}

ssize_t utilReadFromFd(int fd, void *buf, size_t len)
{
	uint8_t *charbuf = (uint8_t *) buf;

	size_t readSz = 0;
	while (readSz < len) {
		ssize_t sz = read(fd, &charbuf[readSz], len - readSz);
		if (sz < 0 && errno == EINTR)
			continue;

		if (sz <= 0)
			break;

		readSz += sz;
	}
	return readSz;
}

ssize_t utilReadFromFile(const char *fname, void *buf, size_t len)
{
	int fd;
	TEMP_FAILURE_RETRY(fd = open(fname, O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		LOG_E("open('%s', O_RDONLY|O_CLOEXEC)", fname);
		return -1;
	}
	ssize_t ret = utilReadFromFd(fd, buf, len);
	close(fd);
	return ret;
}

ssize_t utilWriteToFd(int fd, const void *buf, size_t len)
{
	const uint8_t *charbuf = (const uint8_t *)buf;

	size_t writtenSz = 0;
	while (writtenSz < len) {
		ssize_t sz = write(fd, &charbuf[writtenSz], len - writtenSz);
		if (sz < 0 && errno == EINTR)
			continue;

		if (sz < 0)
			return false;

		writtenSz += sz;
	}
	return true;
}

bool utilWriteBufToFile(const char *filename, const void *buf, size_t len, int open_flags)
{
	int fd;
	TEMP_FAILURE_RETRY(fd = open(filename, open_flags, 0644));
	if (fd == -1) {
		PLOG_E("Couldn't open '%s' for writing", filename);
		return false;
	}

	if (utilWriteToFd(fd, buf, len) == false) {
		PLOG_E("Couldn't write '%zu' bytes to file '%s' (fd='%d')", len, filename, fd);
		close(fd);
		unlink(filename);
		return false;
	}

	LOG_D("Written '%zu' bytes to '%s'", len, filename);

	close(fd);
	return true;
}

bool utilCreateDirRecursively(const char *dir)
{
	if (dir[0] != '/') {
		LOG_W("The directory path must start with '/': '%s' provided", dir);
		return false;
	}

	int prev_dir_fd = open("/", O_RDONLY | O_CLOEXEC);
	if (prev_dir_fd == -1) {
		PLOG_E("open('/', O_RDONLY | O_CLOEXEC)");
		return false;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s", dir);
	char *curr = path;
	for (;;) {
		while (*curr == '/') {
			curr++;
		}

		char *next = strchr(curr, '/');
		if (next == NULL) {
			close(prev_dir_fd);
			return true;
		}
		*next = '\0';

		if (mkdirat(prev_dir_fd, curr, 0755) == -1 && errno != EEXIST) {
			PLOG_E("mkdir('%s', 0755)", curr);
			close(prev_dir_fd);
			return false;
		}

		int dir_fd = TEMP_FAILURE_RETRY(openat(prev_dir_fd, curr, O_DIRECTORY | O_CLOEXEC));
		if (dir_fd == -1) {
			PLOG_E("openat('%d', '%s', O_DIRECTORY | O_CLOEXEC)", prev_dir_fd, curr);
			close(prev_dir_fd);
			return false;
		}
		close(prev_dir_fd);
		prev_dir_fd = dir_fd;
		curr = next + 1;
	}
}

int utilSSnPrintf(char *str, size_t size, const char *format, ...)
{
	char buf1[size];
	char buf2[size];

	snprintf(buf1, sizeof(buf1), "%s", str);

	va_list args;
	va_start(args, format);
	vsnprintf(buf2, size, format, args);
	va_end(args);

	return snprintf(str, size, "%s%s", buf1, buf2);
}
