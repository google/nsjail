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
#include <atomic>
#include <cerrno>
#include <memory>
#include <vector>

#include "cgroup2.h"
#include "cmdline.h"
#include "logs.h"
#include "macros.h"
#include "net.h"
#include "sandbox.h"
#include "subproc.h"
#include "util.h"

namespace nsjail {

static __thread std::atomic<int> sigFatal(0);
static __thread std::atomic<bool> showProc(false);

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

static bool setTimer(nsj_t* nsj) {
	if (nsj->njc.mode() == nsjail::Mode::EXECVE) {
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

static bool pipeTraffic(nsj_t* nsj, int listenfd) {
	std::vector<struct pollfd> fds;
	fds.reserve(nsj->pipes.size() * 3 + 1);
	for (const auto& p : nsj->pipes) {
		fds.push_back({
		    .fd = p.sock_fd,
		    .events = POLLIN | POLLOUT,
		    .revents = 0,
		});
		fds.push_back({
		    .fd = p.pipe_in,
		    .events = POLLOUT,
		    .revents = 0,
		});
		fds.push_back({
		    .fd = p.pipe_out,
		    .events = POLLIN,
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
		for (size_t i = 0; i < fds.size() - 1; ++i) {
			if (fds[i].revents & POLLIN) {
				fds[i].events &= ~POLLIN;
			}
			if (fds[i].revents & POLLOUT) {
				fds[i].events &= ~POLLOUT;
			}
		}
		for (size_t i = 0; i < fds.size() - 3; i += 3) {
			const size_t pipe_no = i / 3;
			int in, out;
			const char* direction;
			bool closed = false;
			std::tuple<int, int, const char*> direction_map[] = {
			    std::make_tuple(i, i + 1, "in"),
			    std::make_tuple(i + 2, i, "out"),
			};
			for (const auto& entry : direction_map) {
				std::tie(in, out, direction) = entry;
				bool in_ready = (fds[in].events & POLLIN) == 0 ||
						(fds[in].revents & POLLIN) == POLLIN;
				bool out_ready = (fds[out].events & POLLOUT) == 0 ||
						 (fds[out].revents & POLLOUT) == POLLOUT;
				if (in_ready && out_ready) {
					LOG_D("#%zu piping data %s", pipe_no, direction);
					ssize_t rv = splice(fds[in].fd, nullptr, fds[out].fd,
					    nullptr, 4096, SPLICE_F_NONBLOCK);
					if (rv == -1 && errno != EAGAIN) {
						PLOG_E("splice fd pair #%zu {%d, %d}\n", pipe_no,
						    fds[in].fd, fds[out].fd);
					}
					if (rv == 0) {
						closed = true;
					}
					fds[in].events |= POLLIN;
					fds[out].events |= POLLOUT;
				}
				if ((fds[in].revents & (POLLERR | POLLHUP)) != 0 ||
				    (fds[out].revents & (POLLERR | POLLHUP)) != 0) {
					closed = true;
				}
			}
			if (closed) {
				LOG_D("#%zu connection closed", pipe_no);
				cleanup = true;
				close(nsj->pipes[pipe_no].sock_fd);
				close(nsj->pipes[pipe_no].pipe_in);
				close(nsj->pipes[pipe_no].pipe_out);
				if (nsj->pipes[pipe_no].pid > 0) {
					kill(nsj->pipes[pipe_no].pid, SIGKILL);
				}
				nsj->pipes[pipe_no] = {};
			}
		}
		if (cleanup) {
			break;
		}
	}
	nsj->pipes.erase(
	    std::remove(nsj->pipes.begin(), nsj->pipes.end(), pipemap_t{}), nsj->pipes.end());
	return false;
}

static int listenMode(nsj_t* nsj) {
	int listenfd = net::getRecvSocket(nsj);
	if (listenfd == -1) {
		return EXIT_FAILURE;
	}
	for (;;) {
		if (sigFatal > 0) {
			subproc::killAndReapAll(
			    nsj, nsj->njc.forward_signals() ? sigFatal.load() : SIGKILL);
			logs::logStop(sigFatal);
			close(listenfd);
			return EXIT_SUCCESS;
		}
		if (showProc) {
			showProc = false;
			subproc::displayProc(nsj);
		}
		if (pipeTraffic(nsj, listenfd)) {
			int connfd = net::acceptConn(listenfd);
			if (connfd >= 0) {
				int in[2];
				int out[2];
				if (pipe(in) != 0 || pipe(out) != 0) {
					PLOG_E("pipe");
					continue;
				}

				pid_t pid = subproc::runChild(nsj, connfd, in[0], out[1], out[1]);

				close(in[0]);
				close(out[1]);

				if (pid <= 0) {
					close(in[1]);
					close(out[0]);
					close(connfd);
				} else {
					nsj->pipes.push_back({
					    .sock_fd = connfd,
					    .pipe_in = in[1],
					    .pipe_out = out[0],
					    .pid = pid,
					});
				}
			}
		}
		subproc::reapProc(nsj);
	}
}

static int standaloneMode(nsj_t* nsj) {
	for (;;) {
		if (subproc::runChild(
			nsj, /* netfd= */ -1, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO) == -1) {
			LOG_E("Couldn't launch the child process");
			return 0xff;
		}
		for (;;) {
			int child_status = subproc::reapProc(nsj);
			if (subproc::countProc(nsj) == 0) {
				if (nsj->njc.mode() == nsjail::Mode::ONCE) {
					return child_status;
				}
				break;
			}
			if (showProc) {
				showProc = false;
				subproc::displayProc(nsj);
			}
			if (sigFatal > 0) {
				subproc::killAndReapAll(
				    nsj, nsj->njc.forward_signals() ? sigFatal.load() : SIGKILL);
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
	std::unique_ptr<nsj_t> nsj = cmdline::parseArgs(argc, argv);
	std::unique_ptr<struct termios> trm = nsjail::getTC(STDIN_FILENO);

	if (!nsj) {
		LOG_F("Couldn't parse cmdline options");
	}
	if (nsj->njc.daemon() && (daemon(/* nochdir= */ 1, /* noclose= */ 0) == -1)) {
		PLOG_F("daemon");
	}
	cmdline::logParams(nsj.get());
	if (!nsjail::setSigHandlers()) {
		LOG_F("nsjail::setSigHandlers() failed");
	}
	if (!nsjail::setTimer(nsj.get())) {
		LOG_F("nsjail::setTimer() failed");
	}

	if (nsj->njc.detect_cgroupv2()) {
		cgroup2::detectCgroupv2(nsj.get());
		LOG_I("Detected cgroups version: %d", nsj->njc.use_cgroupv2() ? 2 : 1);
	}

	if (nsj->njc.use_cgroupv2()) {
		if (!cgroup2::setup(nsj.get())) {
			LOG_E("Couldn't setup parent cgroup (cgroupv2)");
			return -1;
		}
	}

	if (!sandbox::preparePolicy(nsj.get())) {
		LOG_F("Couldn't prepare sandboxing policy");
	}

	int ret = 0;
	if (nsj->njc.mode() == nsjail::Mode::LISTEN) {
		ret = nsjail::listenMode(nsj.get());
	} else {
		ret = nsjail::standaloneMode(nsj.get());
	}

	subproc::killAndReapAll(nsj.get(), SIGKILL);
	sandbox::closePolicy(nsj.get());
	/* Try to restore the underlying console's params in case some program has changed it */
	if (!nsj->njc.daemon()) {
		nsjail::setTC(STDIN_FILENO, trm.get());
	}

	LOG_D("Returning with %d", ret);
	return ret;
}
