/*
   nsjail - regression test: systemExe() must not leak supervisor
   descriptors into external helpers.
   -----------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0
*/

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <vector>

#include "subproc.h"

extern char** environ;

int main() {
	/* Occupy fd 123 the way a supervisor would own an unrelated socket/log fd */
	int tmpfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (tmpfd == -1 || dup2(tmpfd, 123) == -1) {
		std::perror("open/dup2");
		return 1;
	}
	close(tmpfd);

	/*
	 * The helper checks for fd 123 in its own process. Without fd sealing it
	 * inherits the descriptor and exits 42; with sealing the descriptor is
	 * closed by the exec and the helper exits 0.
	 */
	std::vector<std::string> args = {"/bin/sh", "-c", "[ -e /dev/fd/123 ] && exit 42; exit 0"};
	int rc = subproc::systemExe(args, environ);
	if (rc != 0) {
		std::fprintf(stderr, "FAIL: helper observed supervisor fd 123 (rc=%d)\n", rc);
		return 1;
	}
	std::printf("PASS: fd 123 not visible to the helper\n");
	return 0;
}
