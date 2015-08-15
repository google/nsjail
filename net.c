/*

   nsjail - networking routines
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
#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

static bool netSystem(const char *bin, char *const *argv)
{
	int pid = fork();
	if (pid == -1) {
		PLOG_E("fork()");
		return false;
	}
	if (pid == 0) {
		execv(bin, argv);
		PLOG_E("execve('%s')", bin);
		_exit(1);
	}

	for (;;) {
		int status;
		while (wait4(pid, &status, __WALL, NULL) != pid) ;
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0) {
				return true;
			}
			LOG_W("'%s' returned with exit status: %d", bin, WEXITSTATUS(status));
			return false;
		}
		if (WIFSIGNALED(status)) {
			LOG_W("'%s' killed with signal: %d", bin, WTERMSIG(status));
			return false;
		}
		LOG_E("Unknown exit status for '%s' (pid=%d): %d", bin, pid, status);
		kill(pid, SIGKILL);
	}
}

bool netCloneMacVtapAndNS(struct nsjconf_t * nsjconf, int pid)
{
	if (nsjconf->iface == NULL) {
		return true;
	}

	char iface[512];
	snprintf(iface, sizeof(iface), "%s.ns.%d", nsjconf->iface, pid);

#define SBIN_IP_PATH "/sbin/ip"
	char *const argv_add[] =
	    { SBIN_IP_PATH, "link", "add", "link", nsjconf->iface, iface, "type", "macvtap", NULL };
	if (netSystem(SBIN_IP_PATH, argv_add) == false) {
		LOG_E("Couldn't create MACVTAP interface for '%s'", nsjconf->iface);
		return false;
	}

	char pid_str[512];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	char *const argv_netns[] =
	    { SBIN_IP_PATH, "link", "set", "dev", iface, "netns", pid_str, NULL };
	if (netSystem(SBIN_IP_PATH, argv_netns) == false) {
		LOG_E("Couldn't put interface '%s' into NS of PID '%d'", iface, pid);
		return false;
	}

	return true;
}

static bool netIsSocket(int fd)
{
	int optval;
	socklen_t optlen = sizeof(optval);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen);
	if (ret == -1) {
		return false;
	}
	return true;
}

bool netLimitConns(struct nsjconf_t * nsjconf, int connsock)
{
	/* 0 means 'unlimited' */
	if (nsjconf->max_conns_per_ip == 0) {
		return true;
	}

	struct sockaddr_in6 addr;
	char cs_addr[64];
	netConnToText(connsock, true /* remote */ , cs_addr, sizeof(cs_addr), &addr);

	unsigned int cnt = 0;
	struct pids_t *p;
	LIST_FOREACH(p, &nsjconf->pids, pointers) {
		if (memcmp
		    (addr.sin6_addr.s6_addr, p->remote_addr.sin6_addr.s6_addr,
		     sizeof(*p->remote_addr.sin6_addr.s6_addr)) == 0) {
			cnt++;
		}
	}

	if (cnt >= nsjconf->max_conns_per_ip) {
		LOG_W("Rejecting connection from '%s', max_conns_per_ip limit reached: %u", cs_addr,
		      nsjconf->max_conns_per_ip);
		return false;
	}

	return true;
}

int netGetRecvSocket(int port)
{
	if (port < 1 || port > 65535) {
		LOG_F("TCP port %d out of bounds (0 <= port <= 65535)", port);
	}

	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd == -1) {
		PLOG_E("socket(AF_INET6)");
		return -1;
	}
	int so = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(so)) == -1) {
		PLOG_E("setsockopt(%d, SO_REUSEADDR)", sockfd);
		return -1;
	}
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_flowinfo = 0,
		.sin6_addr = in6addr_any,
		.sin6_scope_id = 0,
	};
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		PLOG_E("bind(port:%d)", port);
		return -1;
	}
	if (listen(sockfd, SOMAXCONN) == -1) {
		PLOG_E("listen(%d)", SOMAXCONN);
		return -1;
	}

	char ss_addr[64];
	netConnToText(sockfd, false /* remote */ , ss_addr, sizeof(ss_addr), NULL);
	LOG_I("Listening on %s", ss_addr);

	return sockfd;
}

int netAcceptConn(int listenfd)
{
	struct sockaddr_in6 cli_addr;
	socklen_t socklen = sizeof(cli_addr);
	int connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &socklen);
	if (connfd == -1) {
		if (errno != EINTR) {
			PLOG_E("accept(%d)", listenfd);
		}
		return -1;
	}

	char cs_addr[64], ss_addr[64];
	netConnToText(connfd, true /* remote */ , cs_addr, sizeof(cs_addr), NULL);
	netConnToText(connfd, false /* remote */ , ss_addr, sizeof(ss_addr), NULL);
	LOG_I("New connection from: %s on: %s", cs_addr, ss_addr);

	int so = 1;
	if (setsockopt(connfd, SOL_TCP, TCP_CORK, &so, sizeof(so)) == -1) {
		PLOG_W("setsockopt(%d, TCP_CORK)", connfd);
	}
	return connfd;
}

void netConnToText(int fd, bool remote, char *buf, size_t s, struct sockaddr_in6 *addr_or_null)
{
	if (netIsSocket(fd) == false) {
		snprintf(buf, s, "[STANDALONE_MODE]");
		return;
	}

	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(addr);
	if (remote) {
		if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) == -1) {
			PLOG_W("getpeername(%d)", fd);
			snprintf(buf, s, "[unknown]");
			return;
		}
	} else {
		if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == -1) {
			PLOG_W("getsockname(%d)", fd);
			snprintf(buf, s, "[unknown]");
			return;
		}
	}

	if (addr_or_null) {
		memcpy(addr_or_null, &addr, sizeof(*addr_or_null));
	}

	char tmp[s];
	if (inet_ntop(AF_INET6, addr.sin6_addr.s6_addr, tmp, s) == NULL) {
		PLOG_W("inet_ntop()");
		snprintf(buf, s, "[unknown]:%hu", ntohs(addr.sin6_port));
		return;
	}
	snprintf(buf, s, "%s:%hu", tmp, ntohs(addr.sin6_port));
	return;
}
