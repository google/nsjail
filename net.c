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
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

#define IFACE_NAME "vs"

extern char **environ;

#if defined(NSJAIL_NL3_WITH_MACVLAN)
#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>
bool netInitNsFromParent(struct nsjconf_t * nsjconf, int pid)
{
	if (nsjconf->clone_newnet == false) {
		return true;
	}
	if (nsjconf->iface == NULL) {
		return true;
	}

	struct nl_sock *sk = nl_socket_alloc();
	if (sk == NULL) {
		LOG_E("Could not allocate socket with nl_socket_alloc()");
		return false;
	}
	defer {
		nl_socket_free(sk);
	};

	int err;
	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		LOG_E("Unable to connect socket: %s", nl_geterror(err));
		return false;
	}

	struct rtnl_link *rmv = rtnl_link_macvlan_alloc();
	if (rmv == NULL) {
		LOG_E("rtnl_link_macvlan_alloc(): %s", nl_geterror(err));
		return false;
	}
	defer {
		rtnl_link_put(rmv);
	};

	struct nl_cache *link_cache;
	if ((err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) < 0) {
		LOG_E("rtnl_link_alloc_cache(): %s", nl_geterror(err));
		return false;
	}
	defer {
		nl_cache_free(link_cache);
	};

	int master_index = rtnl_link_name2i(link_cache, nsjconf->iface);
	if (master_index == 0) {
		LOG_E("rtnl_link_name2i(): Did not find '%s' interface", nsjconf->iface);
		return false;
	}

	rtnl_link_set_name(rmv, IFACE_NAME);
	rtnl_link_set_link(rmv, master_index);
	rtnl_link_set_ns_pid(rmv, pid);

	if ((err = rtnl_link_add(sk, rmv, NLM_F_CREATE)) < 0) {
		LOG_E("rtnl_link_add(): %s", nl_geterror(err));
		return false;
	}

	return true;
}
#else				// defined(NSJAIL_NL3_WITH_MACVLAN)
static bool netSystemSbinIp(struct nsjconf_t *nsjconf, char *const *argv)
{
	if (nsjconf->clone_newnet == false) {
		LOG_W
		    ("CLONE_NEWNET not enabled. All changes would affect the global networking namespace");
		return false;
	}

	int pid = fork();
	if (pid == -1) {
		PLOG_E("fork()");
		return false;
	}
	if (pid == 0) {
		execve("/sbin/ip", argv, environ);
		PLOG_E("execve('/sbin/ip'");
		_exit(1);
	}

	for (;;) {
		int status;
		while (wait4(pid, &status, __WALL, NULL) != pid) ;
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0) {
				return true;
			}
			LOG_W("'/sbin/ip' returned with exit status: %d", WEXITSTATUS(status));
			return false;
		}
		if (WIFSIGNALED(status)) {
			LOG_W("'/sbin/ip' killed with signal: %d", WTERMSIG(status));
			return false;
		}
		if (WIFSTOPPED(status)) {
			continue;
		}
		if (WIFCONTINUED(status)) {
			continue;
		}
		LOG_W("Unknown exit status for '/sbin/ip' (pid=%d): %d", pid, status);
		kill(pid, SIGKILL);
	}
}

bool netInitNsFromParent(struct nsjconf_t *nsjconf, int pid)
{
	if (nsjconf->clone_newnet == false) {
		return true;
	}
	if (nsjconf->iface == NULL) {
		return true;
	}

	char pid_str[256];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);

	char *const argv_add[] =
	    { "ip", "link", "add", "link", (char *)nsjconf->iface, "name", IFACE_NAME, "netns",
		pid_str, "type", "macvlan", "mode", "bridge", NULL
	};
	if (netSystemSbinIp(nsjconf, argv_add) == false) {
		LOG_E("Couldn't create MACVTAP interface for '%s'", nsjconf->iface);
		return false;
	}

	return true;
}
#endif				// defined(NSJAIL_NL3_WITH_MACVLAN)

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
	TAILQ_FOREACH(p, &nsjconf->pids, pointers) {
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

int netGetRecvSocket(const char *bindhost, int port)
{
	if (port < 1 || port > 65535) {
		LOG_F("TCP port %d out of bounds (0 <= port <= 65535)", port);
	}

	struct in6_addr in6a;
	if (inet_pton(AF_INET6, bindhost, &in6a) != 1) {
		PLOG_E("Couldn't convert '%s' into AF_INET6 address", bindhost);
		return -1;
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
		.sin6_addr = in6a,
		.sin6_scope_id = 0,
	};
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		TEMP_FAILURE_RETRY(close(sockfd));
		PLOG_E("bind(host:[%s], port:%d)", bindhost, port);
		return -1;
	}
	if (listen(sockfd, SOMAXCONN) == -1) {
		TEMP_FAILURE_RETRY(close(sockfd));
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
	snprintf(buf, s, "[%s]:%hu", tmp, ntohs(addr.sin6_port));
	return;
}

static bool netIfaceUp(const char *ifacename)
{
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}
	defer {
		TEMP_FAILURE_RETRY(close(sock));
	};

	struct ifreq ifr;
	memset(&ifr, '\0', sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifacename);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCGIFFLAGS, IFF_UP)", ifacename);
		return false;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFFLAGS, IFF_UP)", ifacename);
		return false;
	}

	return true;
}

static bool netConfigureVs(struct nsjconf_t *nsjconf)
{
	struct ifreq ifr;
	memset(&ifr, '\0', sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", IFACE_NAME);
	struct in_addr addr;

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}
	defer {
		TEMP_FAILURE_RETRY(close(sock));
	};

	if (inet_pton(AF_INET, nsjconf->iface_vs_ip, &addr) != 1) {
		PLOG_E("Cannot convert '%s' into an IPv4 address", nsjconf->iface_vs_ip);
		return false;
	}
	if (addr.s_addr == INADDR_ANY) {
		LOG_I("IPv4 address for interface '%s' not set", IFACE_NAME);
		return true;
	}

	struct sockaddr_in *sa = (struct sockaddr_in *)(&ifr.ifr_addr);
	sa->sin_family = AF_INET;
	sa->sin_addr = addr;
	if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFADDR, '%s')", IFACE_NAME, nsjconf->iface_vs_ip);
		return false;
	}

	if (inet_pton(AF_INET, nsjconf->iface_vs_nm, &addr) != 1) {
		PLOG_E("Cannot convert '%s' into a IPv4 netmask", nsjconf->iface_vs_nm);
		return false;
	}
	sa->sin_family = AF_INET;
	sa->sin_addr = addr;
	if (ioctl(sock, SIOCSIFNETMASK, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFNETMASK, '%s')", IFACE_NAME, nsjconf->iface_vs_nm);
		return false;
	}

	if (netIfaceUp(IFACE_NAME) == false) {
		return false;
	}

	if (inet_pton(AF_INET, nsjconf->iface_vs_gw, &addr) != 1) {
		PLOG_E("Cannot convert '%s' into a IPv4 GW address", nsjconf->iface_vs_gw);
		return false;
	}
	if (addr.s_addr == INADDR_ANY) {
		LOG_I("Gateway address for '%s' is not set", IFACE_NAME);
		return true;
	}

	struct rtentry rt;
	memset(&rt, '\0', sizeof(rt));

	struct sockaddr_in *sdest = (struct sockaddr_in *)(&rt.rt_dst);
	struct sockaddr_in *smask = (struct sockaddr_in *)(&rt.rt_genmask);
	struct sockaddr_in *sgate = (struct sockaddr_in *)(&rt.rt_gateway);
	sdest->sin_family = AF_INET;
	sdest->sin_addr.s_addr = INADDR_ANY;
	smask->sin_family = AF_INET;
	smask->sin_addr.s_addr = INADDR_ANY;
	sgate->sin_family = AF_INET;
	sgate->sin_addr = addr;

	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	rt.rt_dev = IFACE_NAME;

	if (ioctl(sock, SIOCADDRT, &rt) == -1) {
		PLOG_E("ioctl(SIOCADDRT, '%s')", nsjconf->iface_vs_gw);
		return false;
	}

	return true;
}

bool netInitNsFromChild(struct nsjconf_t * nsjconf)
{
	if (nsjconf->clone_newnet == false) {
		return true;
	}
	if (nsjconf->iface_no_lo == false) {
		if (netIfaceUp("lo") == false) {
			return false;
		}
	}
	if (nsjconf->iface) {
		if (netConfigureVs(nsjconf) == false) {
			return false;
		}
	}
	return true;
}
