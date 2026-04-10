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
#if __has_include(<linux/close_range.h>)
#include <linux/close_range.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <memory>
#include <thread>
#include <vector>

#include "cgroup2.h"
#include "cmdline.h"
#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "monitor.h"
#include "net.h"
#include "sandbox.h"
#include "subproc.h"
#include "unotify/stats.h"
#include "util.h"

namespace nsjail {

/*
 * Thread-local to the main thread. Signals are only delivered to the main thread
 * (monitor threads block them), and only the main thread reads these in its poll loops.
 * See "The Threading Model Comprehension Law" in goal.md.
 */
static __thread std::atomic<int> sigFatal{0};
static __thread std::atomic<bool> showProc{false};

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

int getSigFatal() {
	return sigFatal;
}
bool shouldShowProc() {
	return showProc;
}
void clearShowProc() {
	showProc = false;
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
	if (nsj->njc.mode() == ::nsjail::Mode::EXECVE) {
		return true;
	}

	struct itimerval it = {
	    .it_interval =
		{
		    .tv_sec = 1,
		    .tv_usec = 0,
		},
	    .it_value = {
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

static bool setFDLimit() {
	constexpr uint64_t kRLimitNoFileDesired = 8192ULL;

	struct rlimit64 rl;
	if (util::getrlimit(RLIMIT_NOFILE, &rl) == -1) {
		return false;
	}
	if (rl.rlim_cur >= kRLimitNoFileDesired) {
		return true;
	}
	uint64_t target = std::min((uint64_t)kRLimitNoFileDesired, (uint64_t)rl.rlim_max);
	if (target <= rl.rlim_cur) {
		return true;
	}
	rl.rlim_cur = target;
	if (util::setrlimit(RLIMIT_NOFILE, rl) == -1) {
		PLOG_W("util::setrlimit(RLIMIT_NOFILE, %" PRIu64 ") failed", (uint64_t)rl.rlim_cur);
		return false;
	}
	LOG_D("Increased RLIMIT_NOFILE to %" PRIu64, (uint64_t)rl.rlim_cur);
	return true;
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
	/*
	 * Hard minimum: clone3 (5.3), CLONE_PIDFD (5.4),
	 * CLONE_CLEAR_SIGHAND (5.5), PIDFD_NONBLOCK (5.10),
	 * CLOSE_RANGE_CLOEXEC (5.11).
	 */
	if (!util::kernelVersionAtLeast(5, 11, 0)) {
		LOG_F("This version of nsjail requires Linux >= 5.11. "
		      "Use an earlier version of nsjail for older kernels.");
	}
	if (!util::kernelVersionAtLeast(6, 0, 0)) {
		LOG_D("Running on a kernel older than 6.0. Consider upgrading "
		      "for best compatibility.");
	}
	std::unique_ptr<nsj_t> nsj = cmdline::parseArgs(argc, argv);
	LOG_D("Config:\n%s",  nsj->njc.DebugString().c_str());

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
	if (!nsjail::setFDLimit()) {
		LOG_E("nsjail::setFDLimit() failed");
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
	if (nsj->njc.mode() == ::nsjail::Mode::LISTEN) {
		ret = monitor::runListenMode(nsj.get());
	} else {
		ret = monitor::runStandaloneMode(nsj.get());
	}

	subproc::killAll(nsj.get(), SIGKILL);
	sandbox::closePolicy(nsj.get());
	unotify::printStats(nsj.get());
	/* Try to restore the underlying console's params in case some program has changed it */
	if (!nsj->njc.daemon()) {
		nsjail::setTC(STDIN_FILENO, trm.get());
	}

	LOG_D("Returning with %d", ret);
	return ret;
}
