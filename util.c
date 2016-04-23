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
#include <stdlib.h>
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

bool utilWriteBufToFile(char *filename, const void *buf, size_t len, int open_flags)
{
	int fd = open(filename, open_flags, 0644);
	if (fd == -1) {
		PLOG_E("Couldn't open '%s' for R/O", filename);
		return false;
	}
	defer {
		close(fd);
	};

	if (utilWriteToFd(fd, buf, len) == false) {
		PLOG_E("Couldn't write '%zu' bytes to file '%s' (fd='%d')", len, filename, fd);
		unlink(filename);
		return false;
	}

	LOG_D("Written '%zu' bytes to '%s'", len, filename);

	return true;
}
