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

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "cmdline.h"
#include "common.h"
#include "log.h"
#include "net.h"
#include "subproc.h"

static __thread int nsjailSigFatal = 0;
static __thread bool nsjailShowProc = false;

static void nsjailSig(int sig)
{
	if (sig == SIGALRM) {
		return;
	}
	if (sig == SIGCHLD) {
		return;
	}
	if (sig == SIGUSR1) {
		nsjailShowProc = true;
		return;
	}
	nsjailSigFatal = sig;
}

static bool nsjailSetSigHandler(int sig)
{
	LOG_D("Setting sighandler for signal '%d' (%s)", sig, strsignal(sig));

	sigset_t smask;
	sigemptyset(&smask);
	struct sigaction sa = {
		.sa_handler = nsjailSig,
		.sa_mask = smask,
		.sa_flags = 0,
		.sa_restorer = NULL,
	};
	if (sigaction(sig, &sa, NULL) == -1) {
		PLOG_E("sigaction(%d)", sig);
		return false;
	}
	return true;
}

static bool nsjailSetSigHandlers(void)
{
	if (nsjailSetSigHandler(SIGINT) == false) {
		return false;
	}
	if (nsjailSetSigHandler(SIGUSR1) == false) {
		return false;
	}
	if (nsjailSetSigHandler(SIGALRM) == false) {
		return false;
	}
	if (nsjailSetSigHandler(SIGCHLD) == false) {
		return false;
	}
	if (nsjailSetSigHandler(SIGTERM) == false) {
		return false;
	}
	return true;
}

static bool nsjailSetTimer(struct nsjconf_t *nsjconf)
{
	if (nsjconf->mode == MODE_STANDALONE_EXECVE) {
		return true;
	}

	struct itimerval it = {
		.it_value = {.tv_sec = 1,.tv_usec = 0},
		.it_interval = {.tv_sec = 1,.tv_usec = 0},
	};
	if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
		PLOG_E("setitimer(ITIMER_REAL)");
		return false;
	}
	return true;
}

static void nsjailListenMode(struct nsjconf_t *nsjconf)
{
	int listenfd = netGetRecvSocket(nsjconf->port);
	if (listenfd == -1) {
		return;
	}
	for (;;) {
		if (nsjailSigFatal > 0) {
			subprocKillAll(nsjconf);
			logStop(nsjailSigFatal);
			return;
		}
		if (nsjailShowProc == true) {
			nsjailShowProc = false;
			subprocDisplay(nsjconf);
		}
		int connfd = netAcceptConn(listenfd);
		if (connfd >= 0) {
			subprocRunChild(nsjconf, connfd, connfd, connfd);
			close(connfd);
		}
		subprocReap(nsjconf);
	}
}

static int nsjailStandaloneMode(struct nsjconf_t *nsjconf)
{
	int child_status = 0;
	subprocRunChild(nsjconf, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO);
	for (;;) {
		if (subprocCount(nsjconf) == 0) {
			if (nsjconf->mode == MODE_STANDALONE_ONCE) {
				return child_status;
			}
			subprocRunChild(nsjconf, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO);
		}
		if (nsjailShowProc == true) {
			nsjailShowProc = false;
			subprocDisplay(nsjconf);
		}
		if (nsjailSigFatal > 0) {
			subprocKillAll(nsjconf);
			logStop(nsjailSigFatal);
			return -1;
		}
		pause();
		child_status = subprocReap(nsjconf);
	}
	// not reached
	return child_status;
}

int main(int argc, char *argv[])
{
	struct nsjconf_t nsjconf;
	if (!cmdlineParse(argc, argv, &nsjconf)) {
		exit(1);
	}
	if (nsjconf.clone_newuser == false && geteuid() != 0) {
		LOG_W("--disable_clone_newuser requires root() privs");
	}
	if (nsjconf.daemonize && (daemon(0, 0) == -1)) {
		PLOG_F("daemon");
	}
	cmdlineLogParams(&nsjconf);
	if (nsjailSetSigHandlers() == false) {
		exit(1);
	}
	if (nsjailSetTimer(&nsjconf) == false) {
		exit(1);
	}

	if (nsjconf.mode == MODE_LISTEN_TCP) {
		nsjailListenMode(&nsjconf);
	} else {
		return nsjailStandaloneMode(&nsjconf);
	}
	return 0;
}
