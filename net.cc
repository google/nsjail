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
#include <linux/fib_rules.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#ifdef HAVE_LIBNL3
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "nstun/nstun.h"
#include "util.h"

#define STR_(x) #x
#define STR(x) STR_(x)

#if !defined(F_SEAL_FUTURE_WRITE)
#define F_SEAL_FUTURE_WRITE 0x0010
#endif /* !defined(F_SEAL_FUTURE_WRITE) */

/* Embed pasta inside this binary */
// clang-format off
__asm__("\n"
	"   .section .rodata\n"
	"   .local pasta_start\n"
	"   .local pasta_end\n"
	"pasta_start:\n"
#if defined(PASTA_BIN_PATH)
	"   .incbin " STR(PASTA_BIN_PATH) "\n"
#endif	// defined(PASTA_BIN_PATH)
	"pasta_end:\n"
	"\n");
// clang-format on

static int getPastaFd() {
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
	extern uint8_t* pasta_start;
	extern uint8_t* pasta_end;
	ptrdiff_t len = (uintptr_t)&pasta_end - (uintptr_t)&pasta_start;
	if (len <= 16) { /* Some reasonably safe value accounting for alignment */
		LOG_D("'pasta' is not embedded in this file, len=%td (<=16)", len);
		return -1;
	}

	int fd = util::syscall(__NR_memfd_create, (uintptr_t)"nsjail_pasta",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
	if (fd == -1) {
		fd = util::syscall(
		    __NR_memfd_create, (uintptr_t)"nsjail_pasta", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	}
	if (fd == -1) {
		PLOG_W("Couldn't memfd_create() a file");
		return -1;
	}

	if (!util::writeToFd(fd, &pasta_start, len)) {
		close(fd);
		return -1;
	}
	if (fchmod(fd, 0555) == -1) {
		PLOG_W("fchmod(fd=%d, 0555)", fd);
	}
	if (fcntl(fd, F_ADD_SEALS,
		F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) ==
	    -1) {
		PLOG_W("fcntl(fd=%d F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | "
		       "F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)",
		    fd);
	}
	return fd;
}

extern char** environ;

namespace net {

#define IFACE_NAME "vs"

#include <linux/if_ether.h>
#ifdef HAVE_LIBNL3
#include <linux/rtnetlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>
#endif

#ifdef HAVE_LIBNL3
static bool cloneIface(nsj_t* nsj, struct nl_sock* sk, struct nl_cache* link_cache, int pid) {
	struct rtnl_link* rmv = rtnl_link_macvlan_alloc();
	if (rmv == nullptr) {
		LOG_E("rtnl_link_macvlan_alloc()");
		return false;
	}

	int err;
	int master_index = rtnl_link_name2i(link_cache, nsj->njc.macvlan_iface().c_str());
	if (!master_index) {
		LOG_E("rtnl_link_name2i(): Did not find '%s' interface",
		    nsj->njc.macvlan_iface().c_str());
		rtnl_link_put(rmv);
		return false;
	}

	rtnl_link_set_name(rmv, IFACE_NAME);
	rtnl_link_set_link(rmv, master_index);
	rtnl_link_set_ns_pid(rmv, pid);

	if (nsj->njc.macvlan_vs_ma() != "") {
		struct nl_addr* nladdr = nullptr;
		if ((err = nl_addr_parse(nsj->njc.macvlan_vs_ma().c_str(), AF_LLC, &nladdr)) < 0) {
			LOG_E("nl_addr_parse('%s', AF_LLC) failed: %s",
			    nsj->njc.macvlan_vs_ma().c_str(), nl_geterror(err));
			return false;
		}
		rtnl_link_set_addr(rmv, nladdr);
		nl_addr_put(nladdr);
	}

	if ((err = rtnl_link_macvlan_set_mode(
		 rmv, rtnl_link_macvlan_str2mode(nsj->njc.macvlan_vs_mo().c_str()))) < 0) {
		LOG_E("rtnl_link_macvlan_set_mode(mode:'%s') failed: %s",
		    nsj->njc.macvlan_vs_mo().c_str(), nl_geterror(err));
	}

	if ((err = rtnl_link_add(sk, rmv, NLM_F_CREATE)) < 0) {
		LOG_E("rtnl_link_add(name:'%s' link:'%s'): %s", IFACE_NAME,
		    nsj->njc.macvlan_iface().c_str(), nl_geterror(err));
		rtnl_link_put(rmv);
		return false;
	}

	rtnl_link_put(rmv);
	return true;
}
#endif

#ifdef HAVE_LIBNL3
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
#endif

static void pastaProcess(nsj_t* nsj, int pid, int err_pipe) {
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		PLOG_W("prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
	}

	std::string pid_str = std::to_string(pid);
	std::vector<const char*> argv;

	argv.push_back("pasta");
	argv.push_back("-f");
	argv.push_back("-q");

	if (nsj->njc.user_net().pasta().nat()) {
		if (!nsj->njc.user_net().pasta().enable_ip4_dhcp()) {
			argv.push_back("--no-dhcp");
		}
		if (!nsj->njc.user_net().pasta().enable_ip6_dhcp()) {
			argv.push_back("--no-dhcpv6");
		}
		if (!nsj->njc.user_net().pasta().enable_ip6_ra()) {
			argv.push_back("--no-ra");
		}

		if (!nsj->njc.user_net().pasta().enable_ip4_dhcp() &&
		    !nsj->njc.user_net().pasta().enable_ip6_dhcp()) {
			argv.push_back("--config-net");
		}

		if (nsj->njc.user_net().pasta().enable_dns()) {
			argv.push_back("--dhcp-dns");
		}
		if (!nsj->njc.user_net().pasta().dns_forward().empty()) {
			argv.push_back("--dns-forward");
			argv.push_back(nsj->njc.user_net().pasta().dns_forward().c_str());
		}

		if (!nsj->njc.user_net().pasta().enable_tcp()) {
			argv.push_back("--no-tcp");
		}
		if (!nsj->njc.user_net().pasta().enable_udp()) {
			argv.push_back("--no-udp");
		}
		if (!nsj->njc.user_net().pasta().enable_icmp()) {
			argv.push_back("--no-icmp");
		}
		if (!nsj->njc.user_net().pasta().map_gw()) {
			argv.push_back("--no-map-gw");
		}

		if (!nsj->njc.user_net().ip4().empty()) {
			argv.push_back("-a");
			argv.push_back(nsj->njc.user_net().ip4().c_str());
			if (!nsj->njc.user_net().pasta().mask4().empty()) {
				argv.push_back("-n");
				argv.push_back(nsj->njc.user_net().pasta().mask4().c_str());
			}
			if (!nsj->njc.user_net().gw4().empty()) {
				argv.push_back("-g");
				argv.push_back(nsj->njc.user_net().gw4().c_str());
			}
		}

		if (!nsj->njc.user_net().ip6().empty()) {
			argv.push_back("-a");
			argv.push_back(nsj->njc.user_net().ip6().c_str());

			if (!nsj->njc.user_net().gw6().empty()) {
				argv.push_back("-g");
				argv.push_back(nsj->njc.user_net().gw6().c_str());
			}
		}

		if (!nsj->njc.user_net().pasta().ip4_enabled() &&
		    !nsj->njc.user_net().pasta().ip6_enabled()) {
			LOG_E("Both IPv4 and IPv6 disabled for user networking");
			_exit(EXIT_FAILURE);
		}
		if (!nsj->njc.user_net().pasta().ip4_enabled()) {
			argv.push_back("-6");
		}
		if (!nsj->njc.user_net().pasta().ip6_enabled()) {
			argv.push_back("-4");
		}

		if (!nsj->njc.user_net().ns_iface().empty()) {
			argv.push_back("-I");
			argv.push_back(nsj->njc.user_net().ns_iface().c_str());
		}
	}

	if (!nsj->njc.user_net().pasta().tcp_map_in().empty()) {
		argv.push_back("-t");
		argv.push_back(nsj->njc.user_net().pasta().tcp_map_in().c_str());
	}
	if (!nsj->njc.user_net().pasta().udp_map_in().empty()) {
		argv.push_back("-u");
		argv.push_back(nsj->njc.user_net().pasta().udp_map_in().c_str());
	}
	if (!nsj->njc.user_net().pasta().tcp_map_out().empty()) {
		argv.push_back("-T");
		argv.push_back(nsj->njc.user_net().pasta().tcp_map_out().c_str());
	}
	if (!nsj->njc.user_net().pasta().udp_map_out().empty()) {
		argv.push_back("-U");
		argv.push_back(nsj->njc.user_net().pasta().udp_map_out().c_str());
	}

	if (!(nsj->njc.user_net().pasta().nat())) {
		argv.push_back("--splice-only");
	}

	argv.push_back(pid_str.c_str());
	argv.push_back(nullptr);

	int nullfd = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));
	if (nullfd == -1) {
		PLOG_E("Cannot open '/dev/null' - O_RDWR");
		_exit(EXIT_FAILURE);
	}
	if (TEMP_FAILURE_RETRY(dup2(nullfd, STDIN_FILENO)) == -1) {
		PLOG_E("Cannot dup2('/dev/null', fd=%d)", STDIN_FILENO);
		_exit(EXIT_FAILURE);
	}
	if (TEMP_FAILURE_RETRY(dup2(nullfd, STDOUT_FILENO)) == -1) {
		PLOG_E("Cannot dup2('/dev/null', fd=%d)", STDOUT_FILENO);
		_exit(EXIT_FAILURE);
	}
	if (TEMP_FAILURE_RETRY(dup2(nullfd, STDERR_FILENO)) == -1) {
		PLOG_E("Cannot dup2('/dev/null', fd=%d)", STDERR_FILENO);
		_exit(EXIT_FAILURE);
	}
	if (nullfd > STDERR_FILENO) {
		close(nullfd);
	}

	int pasta_fd = getPastaFd();
	const char* pasta_path = getenv("NSJAIL_PASTA_PATH");
	if (pasta_path == NULL) {
		pasta_path = argv[0];
	}

	util::makeRangeCOE(STDERR_FILENO + 1, ~0U);

	/* LOG doesn't use STDERR_FILENO so it's fine to use it */
	int err = 0;
	if (pasta_fd != -1) {
		util::syscall(__NR_execveat, pasta_fd, (uintptr_t)"", (uintptr_t)argv.data(),
		    (uintptr_t)environ, AT_EMPTY_PATH);
		err = errno;
		PLOG_W("execveat(pasta_fd=%d, AT_EMPTY_PATH)", pasta_fd);

	} else {
		execvpe(pasta_path, (char* const*)argv.data(), environ);
		err = errno;
		PLOG_W("execvpe('%s')", pasta_path);
	}

	util::writeToFd(err_pipe, &err, sizeof(err));
}

static bool spawnPasta(nsj_t* nsj, int pid) {
	LOG_D("Spawning pasta for pid=%d", pid);

	int sv[2];
	if (pipe2(sv, O_CLOEXEC) == -1) {
		PLOG_E("pipe2(sv, O_CLOEXEC)");
		return false;
	}

	pid_t ppid = fork();
	if (ppid == -1) {
		close(sv[0]);
		close(sv[1]);
		PLOG_E("fork()");
		return false;
	}

	if (ppid == 0) {
		close(sv[0]);
		pastaProcess(nsj, pid, sv[1]);
		_exit(EXIT_FAILURE);
	}

	close(sv[1]);
	int err;
	if (util::readFromFd(sv[0], &err, sizeof(err)) > 0) {
		close(sv[0]);
		LOG_E("Pasta execution failed, error: %s", strerror(err));
		while (waitpid(ppid, nullptr, 0) == -1 && errno == EINTR);
		return false;
	}

	close(sv[0]);
	nsj->pids[pid].pasta_pid = ppid;
	LOG_I("Spawned pasta for pid=%d, pasta_pid=%d", pid, ppid);
	return true;
}

bool initParent(nsj_t* nsj, pid_t pid, int pipefd) {
	if (nsj->njc.has_user_net()) {
		if (!nsj->njc.clone_newnet()) {
			LOG_E("Support for User-Mode Networking requested but CLONE_NEWNET "
			      "is not enabled");
			return false;
		}
		if (nsj->njc.user_net().backend() == nsjail::NsJailConfig_UserNet_Backend_NSTUN) {
			if (!nstun_init_parent(pipefd, nsj)) {
				LOG_E("nstun_init_parent() failed");
				return false;
			}
		} else if (nsj->njc.user_net().backend() ==
			       nsjail::NsJailConfig_UserNet_Backend_PASTA &&
			   nsj->njc.user_net().has_pasta()) {
			if (!spawnPasta(nsj, pid)) {
				return false;
			}
		}
	}
	if (!nsj->njc.clone_newnet()) {
		return true;
	}
#ifdef HAVE_LIBNL3
	struct nl_sock* sk = nl_socket_alloc();
	if (!sk) {
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

	struct nl_cache* link_cache;
	if ((err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) < 0) {
		LOG_E("rtnl_link_alloc_cache(): %s", nl_geterror(err));
		return false;
	}
	defer {
		nl_cache_free(link_cache);
	};

	for (const auto& iface : nsj->njc.iface_own()) {
		if (!moveToNs(iface, sk, link_cache, pid)) {
			nl_cache_free(link_cache);
			return false;
		}
	}
	if (!nsj->njc.macvlan_iface().empty() && !cloneIface(nsj, sk, link_cache, pid)) {
		nl_cache_free(link_cache);
		return false;
	}

	return true;
#else
	if (!nsj->njc.iface_own().empty() || !nsj->njc.macvlan_iface().empty()) {
		LOG_E("Features requiring Netlink (iface_own, macvlan) are requested but nsjail "
		      "was built without libnl3 support");
		return false;
	}
	return true;
#endif
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

bool limitConns(nsj_t* nsj, int connsock) {
	/* 0 means 'unlimited' */
	if (nsj->njc.max_conns() != 0 && nsj->pids.size() >= nsj->njc.max_conns()) {
		LOG_W("Rejecting connection, max_conns limit reached: %u", nsj->njc.max_conns());
		return false;
	}

	/* 0 means 'unlimited' */
	if (nsj->njc.max_conns_per_ip() == 0) {
		return true;
	}

	struct sockaddr_in6 addr = {};
	auto connstr = connToText(connsock, true /* remote */, &addr);

	unsigned cnt = 0;
	for (const auto& pid : nsj->pids) {
		if (memcmp(addr.sin6_addr.s6_addr, pid.second.remote_addr.sin6_addr.s6_addr,
			sizeof(pid.second.remote_addr.sin6_addr.s6_addr)) == 0) {
			cnt++;
		}
	}
	if (cnt >= nsj->njc.max_conns_per_ip()) {
		LOG_W("Rejecting connection from '%s', max_conns_per_ip limit reached: %u",
		    connstr.c_str(), nsj->njc.max_conns_per_ip());
		return false;
	}

	return true;
}

int getRecvSocket(const nsj_t* nsj) {
	int port = nsj->njc.port();
	std::string bindhost = nsj->njc.bindhost();

	if (port < 0 || port > 65535) {
		LOG_F("TCP port %d out of bounds (0 <= port <= 65535), specify one with --port "
		      "<port>",
		    port);
	}

	char bindaddr[128];
	snprintf(bindaddr, sizeof(bindaddr), "%s", bindhost.c_str());
	struct in_addr in4a;
	if (inet_pton(AF_INET, bindaddr, &in4a) == 1) {
		snprintf(bindaddr, sizeof(bindaddr), "::ffff:%s", bindhost.c_str());
		LOG_D("Converting bind IPv4:'%s' to IPv6:'%s'", bindhost.c_str(), bindaddr);
	}

	struct in6_addr in6a;
	if (inet_pton(AF_INET6, bindaddr, &in6a) != 1) {
		PLOG_E("Couldn't convert '%s' (orig:'%s') into AF_INET6 address", bindaddr,
		    bindhost.c_str());
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
		PLOG_E("bind(host:[%s] (orig:'%s'), port:%d)", bindaddr, bindhost.c_str(), port);
		return -1;
	}
	if (listen(sockfd, SOMAXCONN) == -1) {
		close(sockfd);
		PLOG_E("listen(%d)", SOMAXCONN);
		return -1;
	}

	auto connstr = connToText(sockfd, false /* remote */, nullptr);
	LOG_I("Listening on %s", connstr.c_str());

	return sockfd;
}

int acceptConn(int listenfd) {
	struct sockaddr_in6 cli_addr = {};
	socklen_t socklen = sizeof(cli_addr);
	int connfd = accept4(listenfd, (struct sockaddr*)&cli_addr, &socklen, SOCK_NONBLOCK);
	if (connfd == -1) {
		if (errno != EINTR) {
			PLOG_E("accept(%d)", listenfd);
		}
		return -1;
	}

	auto connremotestr = connToText(connfd, true /* remote */, nullptr);
	auto connlocalstr = connToText(connfd, false /* remote */, nullptr);
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
	defer {
		close(sock);
	};

	struct ifreq ifr = {};
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifacename);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCGIFFLAGS, IFF_UP)", ifacename);
		return false;
	}
	if ((ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)) {
		return true;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(iface='%s', SIOCSIFFLAGS, IFF_UP|IFF_RUNNING)", ifacename);
		return false;
	}

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

	struct ifreq ifr = {};
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

	struct rtentry rt = {};
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

static bool parseIp(const std::string& ip_str, struct in_addr* addr, int* mask) {
	size_t slash = ip_str.find('/');
	std::string ip = ip_str;
	*mask = 32;
	if (slash != std::string::npos) {
		ip = ip_str.substr(0, slash);
		*mask = std::stoi(ip_str.substr(slash + 1));
	}
	return inet_pton(AF_INET, ip.c_str(), addr) == 1;
}

static bool parseIp6(const std::string& ip_str, struct in6_addr* addr, int* mask) {
	size_t slash = ip_str.find('/');
	std::string ip = ip_str;
	*mask = 128;
	if (slash != std::string::npos) {
		ip = ip_str.substr(0, slash);
		*mask = std::stoi(ip_str.substr(slash + 1));
	}
	return inet_pton(AF_INET6, ip.c_str(), addr) == 1;
}

#ifdef HAVE_LIBNL3
static bool applyTrafficRule(
    struct nl_sock* sk, const nsjail::NsJailConfig_TrafficRule& rule, int family) {
	struct rtnl_rule* rtnl_rule = rtnl_rule_alloc();
	if (!rtnl_rule) {
		LOG_E("rtnl_rule_alloc() failed");
		return false;
	}

	rtnl_rule_set_family(rtnl_rule, family);

	if (rule.has_src_ip() && !rule.src_ip().empty()) {
		struct nl_addr* addr;
		if (nl_addr_parse(rule.src_ip().c_str(), family, &addr) < 0) {
			LOG_E("nl_addr_parse(src_ip, %s) failed", rule.src_ip().c_str());
			rtnl_rule_put(rtnl_rule);
			return false;
		}
		rtnl_rule_set_src(rtnl_rule, addr);
		nl_addr_put(addr);
	}
	if (rule.has_dst_ip() && !rule.dst_ip().empty()) {
		struct nl_addr* addr;
		if (nl_addr_parse(rule.dst_ip().c_str(), family, &addr) < 0) {
			LOG_E("nl_addr_parse(dst_ip, %s) failed", rule.dst_ip().c_str());
			rtnl_rule_put(rtnl_rule);
			return false;
		}
		rtnl_rule_set_dst(rtnl_rule, addr);
		nl_addr_put(addr);
	}
	if (rule.has_iif() && !rule.iif().empty()) rtnl_rule_set_iif(rtnl_rule, rule.iif().c_str());
	if (rule.has_oif() && !rule.oif().empty()) rtnl_rule_set_oif(rtnl_rule, rule.oif().c_str());
	if (rule.has_proto() && rule.proto() != nsjail::NsJailConfig_TrafficRule::UNKNOWN_PROTO) {
		switch (rule.proto()) {
		case nsjail::NsJailConfig_TrafficRule::TCP:
			rtnl_rule_set_ipproto(rtnl_rule, IPPROTO_TCP);
			break;
		case nsjail::NsJailConfig_TrafficRule::UDP:
			rtnl_rule_set_ipproto(rtnl_rule, IPPROTO_UDP);
			break;
		case nsjail::NsJailConfig_TrafficRule::ICMP:
			rtnl_rule_set_ipproto(rtnl_rule, IPPROTO_ICMP);
			break;
		case nsjail::NsJailConfig_TrafficRule::ICMPV6:
			rtnl_rule_set_ipproto(rtnl_rule, IPPROTO_ICMPV6);
			break;
		default:
			break;
		}
	}
	if (rule.has_sport()) {
		if (rule.has_sport_end())
			rtnl_rule_set_sport_range(rtnl_rule, rule.sport(), rule.sport_end());
		else
			rtnl_rule_set_sport(rtnl_rule, rule.sport());
	}
	if (rule.has_dport()) {
		if (rule.has_dport_end())
			rtnl_rule_set_dport_range(rtnl_rule, rule.dport(), rule.dport_end());
		else
			rtnl_rule_set_dport(rtnl_rule, rule.dport());
	}

	if (rule.has_action()) {
		if (rule.action() == nsjail::NsJailConfig_TrafficRule::DROP) {
			rtnl_rule_set_action(rtnl_rule, FR_ACT_BLACKHOLE);
		} else if (rule.action() == nsjail::NsJailConfig_TrafficRule::REJECT) {
			rtnl_rule_set_action(rtnl_rule, FR_ACT_UNREACHABLE);

		} else if (rule.action() == nsjail::NsJailConfig_TrafficRule::ALLOW) {
			rtnl_rule_set_action(rtnl_rule, FR_ACT_TO_TBL);
			rtnl_rule_set_table(rtnl_rule, RT_TABLE_MAIN);	// Just pass to main routing
		}
	} else {
		rtnl_rule_set_action(rtnl_rule, FR_ACT_BLACKHOLE);
	}

	int err = rtnl_rule_add(sk, rtnl_rule, NLM_F_CREATE);
	if (err < 0) {
		LOG_E("rtnl_rule_add() failed: %s", nl_geterror(err));
		rtnl_rule_put(rtnl_rule);
		return false;
	}

	rtnl_rule_put(rtnl_rule);
	return true;
}
#endif

bool initNsFromChild(nsj_t* nsj) {
	if (!nsj->njc.clone_newnet()) {
		return true;
	}
	if (!nsj->njc.iface_no_lo() && !ifaceUp("lo")) {
		return false;
	}
	if (!nsj->njc.macvlan_iface().empty() &&
	    !ifaceConfig(IFACE_NAME, nsj->njc.macvlan_vs_ip(), nsj->njc.macvlan_vs_nm(),
		nsj->njc.macvlan_vs_gw())) {
		return false;
	}

#ifdef HAVE_LIBNL3
	if (nsj->njc.traffic_rule_size() > 0) {
		struct nl_sock* sk = nl_socket_alloc();
		if (!sk) {
			LOG_E("nl_socket_alloc() failed");
			return false;
		}
		defer {
			nl_socket_free(sk);
		};
		if (nl_connect(sk, NETLINK_ROUTE) < 0) {
			LOG_E("nl_connect() failed");
			return false;
		}
		for (const auto& rule : nsj->njc.traffic_rule()) {
			int family = (rule.ip_family() == nsjail::NsJailConfig_TrafficRule::IPV6)
					 ? AF_INET6
					 : AF_INET;
			if (!applyTrafficRule(sk, rule, family)) {
				return false;
			}
		}
	}
#else
	if (nsj->njc.traffic_rule_size() > 0) {
		LOG_E("Traffic rules requested but nsjail was built without libnl3 support");
		return false;
	}
#endif

	return true;
}

bool initChildPreSync(nsj_t* nsj, int pipefd) {
	if (nsj->njc.has_user_net()) {
		if (nsj->njc.user_net().backend() == nsjail::NsJailConfig_UserNet_Backend_NSTUN) {
			if (!nstun_init_child(pipefd, nsj)) {
				LOG_E("nstun_init_child() failed");
				return false;
			}
		}
	}
	return true;
}

bool initNs(nsj_t* nsj) {
	return initNsFromChild(nsj);
}

}  // namespace net
