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
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "logs.h"
#include "subproc.h"

extern char** environ;

namespace net {

#define IFACE_NAME "vs"

#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>

static bool cloneIface(
    nsjconf_t* nsjconf, struct nl_sock* sk, struct nl_cache* link_cache, int pid) {
	struct rtnl_link* rmv = rtnl_link_macvlan_alloc();
	if (rmv == NULL) {
		LOG_E("rtnl_link_macvlan_alloc()");
		return false;
	}

	int err;
	int master_index = rtnl_link_name2i(link_cache, nsjconf->iface_vs.c_str());
	if (!master_index) {
		LOG_E("rtnl_link_name2i(): Did not find '%s' interface", nsjconf->iface_vs.c_str());
		rtnl_link_put(rmv);
		return false;
	}

	rtnl_link_set_name(rmv, IFACE_NAME);
	rtnl_link_set_link(rmv, master_index);
	rtnl_link_set_ns_pid(rmv, pid);

	if (nsjconf->iface_vs_ma != "") {
		struct nl_addr* nladdr = nullptr;
		if ((err = nl_addr_parse(nsjconf->iface_vs_ma.c_str(), AF_LLC, &nladdr)) < 0) {
			LOG_E("nl_addr_parse('%s', AF_LLC) failed: %s",
			    nsjconf->iface_vs_ma.c_str(), nl_geterror(err));
			return false;
		}
		rtnl_link_set_addr(rmv, nladdr);
		nl_addr_put(nladdr);
	}

	if ((err = rtnl_link_macvlan_set_mode(
		 rmv, rtnl_link_macvlan_str2mode(nsjconf->iface_vs_mo.c_str()))) < 0) {
		LOG_E("rtnl_link_macvlan_set_mode(mode:'%s') failed: %s",
		    nsjconf->iface_vs_mo.c_str(), nl_geterror(err));
	}

	if ((err = rtnl_link_add(sk, rmv, NLM_F_CREATE)) < 0) {
		LOG_E("rtnl_link_add(name:'%s' link:'%s'): %s", IFACE_NAME,
		    nsjconf->iface_vs.c_str(), nl_geterror(err));
		rtnl_link_put(rmv);
		return false;
	}

	rtnl_link_put(rmv);
	return true;
}

static bool moveToNs(
    const std::string& iface, struct nl_sock* sk, struct nl_cache* link_cache, pid_t pid) {
	LOG_D("Moving interface '%s' into netns=%d", iface.c_str(), (int)pid);

	struct rtnl_link* orig_link = rtnl_link_get_by_name(link_cache, iface.c_str());
	if (!orig_link) {
		LOG_E("Couldn't find interface '%s'", iface.c_str());
		return false;
	}
	struct rtnl_link* new_link = rtnl_link_alloc();
	if (!new_link) {
		LOG_E("Couldn't allocate new link");
		rtnl_link_put(orig_link);
		return false;
	}

	rtnl_link_set_ns_pid(new_link, pid);

	int err = rtnl_link_change(sk, orig_link, new_link, RTM_SETLINK);
	if (err < 0) {
		LOG_E("rtnl_link_change(): set NS of interface '%s' to pid=%d: %s", iface.c_str(),
		    (int)pid, nl_geterror(err));
		rtnl_link_put(new_link);
		rtnl_link_put(orig_link);
		return false;
	}

	rtnl_link_put(new_link);
	rtnl_link_put(orig_link);
	return true;
}

bool initNsFromParent(nsjconf_t* nsjconf, int pid) {
	if (!nsjconf->clone_newnet) {
		return true;
	}
	struct nl_sock* sk = nl_socket_alloc();
	if (!sk) {
		LOG_E("Could not allocate socket with nl_socket_alloc()");
		return false;
	}

	int err;
	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		LOG_E("Unable to connect socket: %s", nl_geterror(err));
		nl_socket_free(sk);
		return false;
	}

	struct nl_cache* link_cache;
	if ((err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) < 0) {
		LOG_E("rtnl_link_alloc_cache(): %s", nl_geterror(err));
		nl_socket_free(sk);
		return false;
	}

	for (const auto& iface : nsjconf->ifaces) {
		if (!moveToNs(iface, sk, link_cache, pid)) {
			nl_cache_free(link_cache);
			nl_socket_free(sk);
			return false;
		}
	}
	if (!nsjconf->iface_vs.empty() && !cloneIface(nsjconf, sk, link_cache, pid)) {
		nl_cache_free(link_cache);
		nl_socket_free(sk);
		return false;
	}

	nl_cache_free(link_cache);
	nl_socket_free(sk);
	return true;
}

static bool isSocket(int fd) {
	int optval;
	socklen_t optlen = sizeof(optval);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen);
	if (ret == -1) {
		return false;
	}
	return true;
}

bool limitConns(nsjconf_t* nsjconf, int connsock) {
	/* 0 means 'unlimited' */
	if (nsjconf->max_conns != 0 && nsjconf->pids.size() >= nsjconf->max_conns) {
		LOG_W("Rejecting connection, max_conns limit reached: %u", nsjconf->max_conns);
		return false;
	}

	/* 0 means 'unlimited' */
	if (nsjconf->max_conns_per_ip == 0) {
		return true;
	}

	struct sockaddr_in6 addr;
	auto connstr = connToText(connsock, true /* remote */, &addr);

	unsigned cnt = 0;
	for (const auto& pid : nsjconf->pids) {
		if (memcmp(addr.sin6_addr.s6_addr, pid.second.remote_addr.sin6_addr.s6_addr,
			sizeof(pid.second.remote_addr.sin6_addr.s6_addr)) == 0) {
			cnt++;
		}
	}
	if (cnt >= nsjconf->max_conns_per_ip) {
		LOG_W("Rejecting connection from '%s', max_conns_per_ip limit reached: %u",
		    connstr.c_str(), nsjconf->max_conns_per_ip);
		return false;
	}

	return true;
}

int getRecvSocket(const char* bindhost, int port) {
	if (port < 0 || port > 65535) {
		LOG_F(
		    "TCP port %d out of bounds (0 <= port <= 65535), specify one with --port "
		    "<port>",
		    port);
	}

	char bindaddr[128];
	snprintf(bindaddr, sizeof(bindaddr), "%s", bindhost);
	struct in_addr in4a;
	if (inet_pton(AF_INET, bindaddr, &in4a) == 1) {
		snprintf(bindaddr, sizeof(bindaddr), "::ffff:%s", bindhost);
		LOG_D("Converting bind IPv4:'%s' to IPv6:'%s'", bindhost, bindaddr);
	}

	struct in6_addr in6a;
	if (inet_pton(AF_INET6, bindaddr, &in6a) != 1) {
		PLOG_E(
		    "Couldn't convert '%s' (orig:'%s') into AF_INET6 address", bindaddr, bindhost);
		return -1;
	}

	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd == -1) {
		PLOG_E("socket(AF_INET6)");
		return -1;
	}
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK)) {
		PLOG_E("fcntl(%d, F_SETFL, O_NONBLOCK)", sockfd);
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
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		close(sockfd);
		PLOG_E("bind(host:[%s] (orig:'%s'), port:%d)", bindaddr, bindhost, port);
		return -1;
	}
	if (listen(sockfd, SOMAXCONN) == -1) {
		close(sockfd);
		PLOG_E("listen(%d)", SOMAXCONN);
		return -1;
	}

	auto connstr = connToText(sockfd, false /* remote */, NULL);
	LOG_I("Listening on %s", connstr.c_str());

	return sockfd;
}

int acceptConn(int listenfd) {
	struct sockaddr_in6 cli_addr;
	socklen_t socklen = sizeof(cli_addr);
	int connfd = accept4(listenfd, (struct sockaddr*)&cli_addr, &socklen, SOCK_NONBLOCK);
	if (connfd == -1) {
		if (errno != EINTR) {
			PLOG_E("accept(%d)", listenfd);
		}
		return -1;
	}

	auto connremotestr = connToText(connfd, true /* remote */, NULL);
	auto connlocalstr = connToText(connfd, false /* remote */, NULL);
	LOG_I("New connection from: %s on: %s", connremotestr.c_str(), connlocalstr.c_str());

	return connfd;
}

const std::string connToText(int fd, bool remote, struct sockaddr_in6* addr_or_null) {
	std::string res;

	if (!isSocket(fd)) {
		return "[STANDALONE MODE]";
	}

	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(addr);
	if (remote) {
		if (getpeername(fd, (struct sockaddr*)&addr, &addrlen) == -1) {
			PLOG_W("getpeername(%d)", fd);
			return "[unknown]";
		}
	} else {
		if (getsockname(fd, (struct sockaddr*)&addr, &addrlen) == -1) {
			PLOG_W("getsockname(%d)", fd);
			return "[unknown]";
		}
	}

	if (addr_or_null) {
		memcpy(addr_or_null, &addr, sizeof(*addr_or_null));
	}

	char addrstr[128];
	if (!inet_ntop(AF_INET6, addr.sin6_addr.s6_addr, addrstr, sizeof(addrstr))) {
		PLOG_W("inet_ntop()");
		snprintf(addrstr, sizeof(addrstr), "[unknown](%s)", strerror(errno));
	}

	res.append("[");
	res.append(addrstr);
	res.append("]:");
	res.append(std::to_string(ntohs(addr.sin6_port)));
	return res;
}

static bool ifaceUp(const char* ifacename) {
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}

	struct ifreq ifr;
	memset(&ifr, '\0', sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifacename);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCGIFFLAGS, IFF_UP)", ifacename);
		close(sock);
		return false;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFFLAGS, IFF_UP|IFF_RUNNING)", ifacename);
		close(sock);
		return false;
	}

	close(sock);
	return true;
}

static bool ifaceConfig(const std::string& iface, const std::string& ip, const std::string& mask,
    const std::string& gw) {
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}

	struct in_addr addr;
	if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
		PLOG_E("Cannot convert '%s' into an IPv4 address", ip.c_str());
		close(sock);
		return false;
	}
	if (addr.s_addr == INADDR_ANY) {
		LOG_D("IPv4 address for interface '%s' not set", iface.c_str());
		close(sock);
		return true;
	}

	struct ifreq ifr;
	memset(&ifr, '\0', sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", iface.c_str());
	struct sockaddr_in* sa = (struct sockaddr_in*)(&ifr.ifr_addr);
	sa->sin_family = AF_INET;
	sa->sin_addr = addr;
	if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFADDR, '%s')", iface.c_str(), ip.c_str());
		close(sock);
		return false;
	}

	if (inet_pton(AF_INET, mask.c_str(), &addr) != 1) {
		PLOG_E("Cannot convert '%s' into a IPv4 netmask", mask.c_str());
		close(sock);
		return false;
	}
	sa->sin_family = AF_INET;
	sa->sin_addr = addr;
	if (ioctl(sock, SIOCSIFNETMASK, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFNETMASK, '%s')", iface.c_str(), mask.c_str());
		close(sock);
		return false;
	}

	if (!ifaceUp(iface.c_str())) {
		close(sock);
		return false;
	}

	if (inet_pton(AF_INET, gw.c_str(), &addr) != 1) {
		PLOG_E("Cannot convert '%s' into a IPv4 GW address", gw.c_str());
		close(sock);
		return false;
	}
	if (addr.s_addr == INADDR_ANY) {
		LOG_D("Gateway address for '%s' is not set", iface.c_str());
		close(sock);
		return true;
	}

	struct rtentry rt;
	memset(&rt, '\0', sizeof(rt));
	struct sockaddr_in* sdest = (struct sockaddr_in*)(&rt.rt_dst);
	struct sockaddr_in* smask = (struct sockaddr_in*)(&rt.rt_genmask);
	struct sockaddr_in* sgate = (struct sockaddr_in*)(&rt.rt_gateway);
	sdest->sin_family = AF_INET;
	sdest->sin_addr.s_addr = INADDR_ANY;
	smask->sin_family = AF_INET;
	smask->sin_addr.s_addr = INADDR_ANY;
	sgate->sin_family = AF_INET;
	sgate->sin_addr = addr;

	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	char rt_dev[IF_NAMESIZE];
	snprintf(rt_dev, sizeof(rt_dev), "%s", iface.c_str());
	rt.rt_dev = rt_dev;

	if (ioctl(sock, SIOCADDRT, &rt) == -1) {
		PLOG_E("ioctl(SIOCADDRT, '%s')", gw.c_str());
		close(sock);
		return false;
	}

	close(sock);
	return true;
}

bool initNsFromChild(nsjconf_t* nsjconf) {
	if (!nsjconf->clone_newnet) {
		return true;
	}
	if (nsjconf->iface_lo && !ifaceUp("lo")) {
		return false;
	}
	if (!nsjconf->iface_vs.empty() && !ifaceConfig(IFACE_NAME, nsjconf->iface_vs_ip,
					      nsjconf->iface_vs_nm, nsjconf->iface_vs_gw)) {
		return false;
	}
	return true;
}

}  // namespace net
