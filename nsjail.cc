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

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <memory>
#include <vector>

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
	if (sig == SIGALRM || sig == SIGCHLD || sig == SIGPIPE) {
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
	}
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

static bool pipeTraffic(nsjconf_t* nsjconf, int listenfd) {
	std::vector<struct pollfd> fds;
	fds.reserve(nsjconf->pipes.size() * 2 + 1);
	for (const auto& p : nsjconf->pipes) {
		fds.push_back({
		    .fd = p.first,
		    .events = POLLIN,
		    .revents = 0,
		});
		fds.push_back({
		    .fd = p.second,
		    .events = POLLOUT,
		    .revents = 0,
		});
	}
	fds.push_back({
	    .fd = listenfd,
	    .events = POLLIN,
	    .revents = 0,
	});
	LOG_D("Waiting for fd activity");
	while (poll(fds.data(), fds.size(), -1) > 0) {
		if (sigFatal > 0 || showProc) {
			return false;
		}
		if (fds.back().revents != 0) {
			LOG_D("New connection ready");
			return true;
		}
		bool cleanup = false;
		for (size_t i = 0; i < fds.size() - 1; i += 2) {
			bool read_ready = fds[i].events == 0 || (fds[i].revents & POLLIN) == POLLIN;
			bool write_ready =
			    fds[i + 1].events == 0 || (fds[i + 1].revents & POLLOUT) == POLLOUT;
			bool pair_closed = (fds[i].revents & (POLLHUP | POLLERR)) != 0 ||
					   (fds[i + 1].revents & (POLLHUP | POLLERR)) != 0;
			if (read_ready && write_ready) {
				LOG_D("Read+write ready on %ld", i / 2);
				ssize_t rv = splice(fds[i].fd, nullptr, fds[i + 1].fd, nullptr,
				    4096, SPLICE_F_NONBLOCK);
				if (rv == -1 && errno != EAGAIN) {
					PLOG_E("splice fd pair #%ld {%d, %d}\n", i / 2, fds[i].fd,
					    fds[i + 1].fd);
				}
				if (rv == 0) {
					pair_closed = true;
				}
				fds[i].events = POLLIN;
				fds[i + 1].events = POLLOUT;
			} else if (read_ready) {
				LOG_D("Read ready on %ld", i / 2);
				fds[i].events = 0;
			} else if (write_ready) {
				LOG_D("Write ready on %ld", i / 2);
				fds[i + 1].events = 0;
			}
			if (pair_closed) {
				LOG_D("Hangup on %ld", i / 2);
				cleanup = true;
				close(fds[i].fd);
				close(fds[i + 1].fd);
				nsjconf->pipes[i / 2] = {0, 0};
			}
		}
		if (cleanup) {
			break;
		}
	}
	nsjconf->pipes.erase(
	    std::remove(nsjconf->pipes.begin(), nsjconf->pipes.end(), std::pair<int, int>(0, 0)),
	    nsjconf->pipes.end());
	return false;
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
		if (pipeTraffic(nsjconf, listenfd)) {
			int connfd = net::acceptConn(listenfd);
			if (connfd >= 0) {
				int in[2];
				int out[2];
				if (pipe(in) != 0 || pipe(out) != 0) {
					PLOG_E("pipe");
					continue;
				}
				nsjconf->pipes.emplace_back(connfd, in[1]);
				nsjconf->pipes.emplace_back(out[0], connfd);
				subproc::runChild(nsjconf, connfd, in[0], out[1], out[1]);
				close(in[0]);
				close(out[1]);
			}
		}
		subproc::reapProc(nsjconf);
	}
}

static int standaloneMode(nsjconf_t* nsjconf) {
	for (;;) {
		if (!subproc::runChild(
			nsjconf, /* netfd= */ -1, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)) {
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
	if (!nsjconf->daemonize) {
		nsjail::setTC(STDIN_FILENO, trm.get());
	}

	LOG_D("Returning with %d", ret);
	return ret;
}
