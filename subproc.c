/*

   nsjail - subprocess management
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

#include "subproc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "contain.h"
#include "log.h"
#include "net.h"
#include "sandbox.h"

static int subprocNewProc(struct nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err, int pipefd)
{
	if (containInitUserNs(nsjconf) == false) {
		exit(1);
	}
	if (containPrepareEnv(nsjconf) == false) {
		exit(1);
	}
	if (containSetupFD(nsjconf, fd_in, fd_out, fd_err, pipefd) == false) {
		exit(1);
	}
	if (containMountFS(nsjconf) == false) {
		exit(1);
	}
	if (containDropPrivs(nsjconf) == false) {
		exit(1);
	}
	/* */
	/* As non-root */
	if (containSetLimits(nsjconf) == false) {
		exit(1);
	}
	if (containMakeFdsCOE() == false) {
		exit(1);
	}
	/* Should be the last one in the sequence */
	if (sandboxApply(nsjconf) == false) {
		exit(1);
	}

	char *const *env = { NULL };
	if (nsjconf->keep_env == true) {
		env = environ;
	}

	LOG_D("Trying to execve('%s')", nsjconf->argv[0]);
	for (int i = 0; nsjconf->argv[i]; i++) {
		LOG_D(" Arg[%d]: '%s'", i, nsjconf->argv[i]);
	}
	execve(nsjconf->argv[0], &nsjconf->argv[0], env);

	PLOG_E("execve('%s') failed", nsjconf->argv[0]);

	_exit(1);
}

static void subprocAdd(struct nsjconf_t *nsjconf, pid_t pid, int sock)
{
	struct pids_t *p = malloc(sizeof(struct pids_t));
	if (p == NULL) {
		PLOG_E("malloc");
		return;
	}

	p->pid = pid;
	p->start = time(NULL);
	netConnToText(sock, true /* remote */ , p->remote_txt, sizeof(p->remote_txt),
		      &p->remote_addr);
	LIST_INSERT_HEAD(&nsjconf->pids, p, pointers);

	LOG_D("Added pid '%d' with start time '%u' to the queue for IP: '%s'", pid,
	      (unsigned int)p->start, p->remote_txt);
}

static void subprocRemove(struct nsjconf_t *nsjconf, pid_t pid)
{
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		if (p->pid == pid) {
			LOG_D("Removing pid '%d' from the queue (IP:'%s', start time:'%u')", p->pid,
			      p->remote_txt, (unsigned int)p->start);
			LIST_REMOVE(p, pointers);
			free(p);
			return;
		}
	}
	LOG_W("PID: %d not found (?)", pid);
}

int subprocCount(struct nsjconf_t *nsjconf)
{
	int cnt = 0;
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		cnt++;
	}
	return cnt;
}

void subprocDisplay(struct nsjconf_t *nsjconf)
{
	LOG_I("Total number of spawned namespaces: %d", subprocCount(nsjconf));
	time_t now = time(NULL);
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		time_t diff = now - p->start;
		time_t left = nsjconf->tlimit ? nsjconf->tlimit - diff : 0;
		LOG_I("PID: %d, Remote host: %s, Run time: %ld sec. (time left: %ld sec.)", p->pid,
		      p->remote_txt, (long)diff, (long)left);
	}
}

int subprocReap(struct nsjconf_t *nsjconf)
{
	int status;
	int rv = 0;
	pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			subprocRemove(nsjconf, pid);
			LOG_I("PID: %d exited with status: %d, (PIDs left: %d)", pid,
			      WEXITSTATUS(status), subprocCount(nsjconf));
			if (rv == 0) {
				rv = WEXITSTATUS(status);
			}
		}
		if (WIFSIGNALED(status)) {
			subprocRemove(nsjconf, pid);
			LOG_I("PID: %d terminated with signal: %d, (PIDs left: %d)", pid,
			      WTERMSIG(status), subprocCount(nsjconf));
		}
	}

	time_t now = time(NULL);
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		if (nsjconf->tlimit == 0) {
			continue;
		}
		pid = p->pid;
		time_t diff = now - p->start;
		if (diff >= nsjconf->tlimit) {
			LOG_I("PID: %d run time >= time limit (%ld >= %ld) (%s). Killing it", pid,
			      (long)diff, (long)nsjconf->tlimit, p->remote_txt);
			/* Probably a kernel bug - some processes cannot be killed with KILL if
			 * they're namespaced, and in a stopped state */
			kill(pid, SIGCONT);
			PLOG_D("Sent SIGCONT to PID: %d", pid);
			kill(pid, SIGKILL);
			PLOG_D("Sent SIGKILL to PID: %d", pid);
			if (rv == 0) {
				rv = -1;
			}
		}
	}
	return rv;
}

void subprocKillAll(struct nsjconf_t *nsjconf)
{
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		kill(p->pid, SIGKILL);
	}
}

void subprocRunChild(struct nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err)
{
	if (netLimitConns(nsjconf, fd_in) == false) {
		return;
	}

	unsigned int flags = 0UL;
	flags |= (nsjconf->clone_newnet ? CLONE_NEWNET : 0);
	flags |= (nsjconf->clone_newuser ? CLONE_NEWUSER : 0);
	flags |= (nsjconf->clone_newns ? CLONE_NEWNS : 0);
	flags |= (nsjconf->clone_newpid ? CLONE_NEWPID : 0);
	flags |= (nsjconf->clone_newipc ? CLONE_NEWIPC : 0);
	flags |= (nsjconf->clone_newuts ? CLONE_NEWUTS : 0);

	if (nsjconf->mode == MODE_STANDALONE_EXECVE) {
		if (nsjconf->clone_newpid) {
			LOG_D("CLONE_NEWPID requested. It causes troubles with unshare() "
			      "[ENOMEM with clone/fork/vfork]. Disabling it");
			flags &= ~(CLONE_NEWPID);
		}
		LOG_D("Entering namespace with flags: %#x", flags);
		if (unshare(flags) == -1) {
			PLOG_E("unshare(%u)", flags);
			_exit(EXIT_FAILURE);
		}
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, -1);
	}

	flags |= SIGCHLD;
	LOG_D("Creating new process with clone flags: %#x", flags);

	int pipefd[2];
	if (pipe2(pipefd, O_CLOEXEC) == -1) {
		PLOG_E("pipe2(pipefd, O_CLOEXEC) failed");
		return;
	}

	pid_t pid = syscall(__NR_clone, (uintptr_t) flags, NULL, NULL, NULL, (uintptr_t) 0);
	if (pid == 0) {
		subprocNewProc(nsjconf, fd_in, fd_out, fd_err, pipefd[1]);
	}
	if (pid == -1) {
		PLOG_E("clone(flags=%#x) failed. You probably need root privileges if your system "
		       "doesn't support CLONE_NEWUSER. Alternatively, you might want to recompile your "
		       "kernel with support for namespaces or check the setting of the "
		       "kernel.unprivileged_userns_clone sysctl", flags);
		return;
	}

	if (netCloneMacVtapAndNS(nsjconf, pid) == false) {
		LOG_E("Couldn't create and put MACVTAP interface into NS of PID '%d'", pid);
	}

	char cs_addr[64];
	netConnToText(fd_in, true /* remote */ , cs_addr, sizeof(cs_addr), NULL);
	LOG_I("PID: %d about to execute '%s' for %s", pid, nsjconf->argv[0], cs_addr);

	char log_buf[4096];
	close(pipefd[1]);
	ssize_t sz;
	while ((sz = read(pipefd[0], log_buf, sizeof(log_buf) - 1)) > 0) {
		log_buf[sz] = '\0';
		logDirectlyToFD(log_buf);
	}
	close(pipefd[0]);

	subprocAdd(nsjconf, pid, fd_in);
}
