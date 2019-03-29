/*

   nsjail
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

#include "nsjail.h"

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include <memory>

#include "cmdline.h"
#include "logs.h"
#include "macros.h"
#include "net.h"
#include "sandbox.h"
#include "subproc.h"
#include "util.h"

namespace nsjail {

static __thread int sigFatal = 0;
static __thread bool showProc = false;

static void sigHandler(int sig) {
	if (sig == SIGALRM) {
		return;
	}
	if (sig == SIGCHLD) {
		return;
	}
	if (sig == SIGUSR1 || sig == SIGQUIT) {
		showProc = true;
		return;
	}
	sigFatal = sig;
}

static bool setSigHandler(int sig) {
	LOG_D("Setting sighandler for signal %s (%d)", util::sigName(sig).c_str(), sig);

	sigset_t smask;
	sigemptyset(&smask);

	struct sigaction sa;
	sa.sa_handler = sigHandler;
	sa.sa_mask = smask;
	sa.sa_flags = 0;
	sa.sa_restorer = NULL;

	if (sig == SIGTTIN || sig == SIGTTOU) {
		sa.sa_handler = SIG_IGN;
	};
	if (sigaction(sig, &sa, NULL) == -1) {
		PLOG_E("sigaction(%d)", sig);
		return false;
	}
	return true;
}

static bool setSigHandlers(void) {
	for (const auto& i : nssigs) {
		if (!setSigHandler(i)) {
			return false;
		}
	}
	return true;
}

static bool setTimer(nsjconf_t* nsjconf) {
	if (nsjconf->mode == MODE_STANDALONE_EXECVE) {
		return true;
	}

	struct itimerval it = {
	    .it_interval =
		{
		    .tv_sec = 1,
		    .tv_usec = 0,
		},
	    .it_value =
		{
		    .tv_sec = 1,
		    .tv_usec = 0,
		},
	};
	if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
		PLOG_E("setitimer(ITIMER_REAL)");
		return false;
	}
	return true;
}

static int listenMode(nsjconf_t* nsjconf) {
	int listenfd = net::getRecvSocket(nsjconf->bindhost.c_str(), nsjconf->port);
	if (listenfd == -1) {
		return EXIT_FAILURE;
	}
	for (;;) {
		if (sigFatal > 0) {
			subproc::killAndReapAll(nsjconf);
			logs::logStop(sigFatal);
			close(listenfd);
			return EXIT_SUCCESS;
		}
		if (showProc) {
			showProc = false;
			subproc::displayProc(nsjconf);
		}
		int connfd = net::acceptConn(listenfd);
		if (connfd >= 0) {
			subproc::runChild(nsjconf, connfd, connfd, connfd);
			close(connfd);
		}
		subproc::reapProc(nsjconf);
	}
}

static int standaloneMode(nsjconf_t* nsjconf) {
	for (;;) {
		if (!subproc::runChild(nsjconf, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)) {
			LOG_E("Couldn't launch the child process");
			return 0xff;
		}
		for (;;) {
			int child_status = subproc::reapProc(nsjconf);
			if (subproc::countProc(nsjconf) == 0) {
				if (nsjconf->mode == MODE_STANDALONE_ONCE) {
					return child_status;
				}
				break;
			}
			if (showProc) {
				showProc = false;
				subproc::displayProc(nsjconf);
			}
			if (sigFatal > 0) {
				subproc::killAndReapAll(nsjconf);
				logs::logStop(sigFatal);
				return (128 + sigFatal);
			}
			pause();
		}
	}
	// not reached
}

std::unique_ptr<struct termios> getTC(int fd) {
	std::unique_ptr<struct termios> trm(new struct termios);

	if (ioctl(fd, TCGETS, trm.get()) == -1) {
		PLOG_D("ioctl(fd=%d, TCGETS) failed", fd);
		return nullptr;
	}
	LOG_D("Saved the current state of the TTY");
	return trm;
}

void setTC(int fd, const struct termios* trm) {
	if (!trm) {
		return;
	}
	if (ioctl(fd, TCSETS, trm) == -1) {
		PLOG_W("ioctl(fd=%d, TCSETS) failed", fd);
		return;
	}
	if (tcflush(fd, TCIFLUSH) == -1) {
		PLOG_W("tcflush(fd=%d, TCIFLUSH) failed", fd);
		return;
	}
}

}  // namespace nsjail

int main(int argc, char* argv[]) {
	std::unique_ptr<nsjconf_t> nsjconf = cmdline::parseArgs(argc, argv);
	std::unique_ptr<struct termios> trm = nsjail::getTC(STDIN_FILENO);

	if (!nsjconf) {
		LOG_F("Couldn't parse cmdline options");
	}
	if (nsjconf->daemonize && (daemon(0, 0) == -1)) {
		PLOG_F("daemon");
	}
	cmdline::logParams(nsjconf.get());
	if (!nsjail::setSigHandlers()) {
		LOG_F("nsjail::setSigHandlers() failed");
	}
	if (!nsjail::setTimer(nsjconf.get())) {
		LOG_F("nsjail::setTimer() failed");
	}
	if (!sandbox::preparePolicy(nsjconf.get())) {
		LOG_F("Couldn't prepare sandboxing policy");
	}

	int ret = 0;
	if (nsjconf->mode == MODE_LISTEN_TCP) {
		ret = nsjail::listenMode(nsjconf.get());
	} else {
		ret = nsjail::standaloneMode(nsjconf.get());
	}

	sandbox::closePolicy(nsjconf.get());
	/* Try to restore the underlying console's params in case some program has changed it */
	nsjail::setTC(STDIN_FILENO, trm.get());

	LOG_D("Returning with %d", ret);
	return ret;
}
