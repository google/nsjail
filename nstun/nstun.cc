#include "nstun.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <set>
#include <vector>

#include "core.h"
#include "icmp.h"
#include "iface.h"
#include "ip.h"
#include "kafel.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tcp.h"
#include "tun.h"
#include "udp.h"
#include "util.h"

/*
 * The network loop parses frames written by the jailed process, so it runs in
 * a separate helper process, not in the supervisor. The supervisor only keeps
 * the helper's pid.
 */
struct nstun_context_handle {
	pid_t helper_pid = -1;
};

namespace nstun {

Context::~Context() {
	/* Owning maps (ipv4_udp_flows_by_key, etc.) will self-clean via std::unique_ptr */
	for (auto& [fd, _] : host_listener_fd_to_rule) {
		::close(fd);
	}
}

static void garbage_collect(Context* ctx) {
	time_t now = time(NULL);

	auto do_gc = [&](auto& map) {
		std::vector<Flow*> stale_flows;
		for (auto const& pair : map) {
			Flow* flow = pair.second.get();
			flow->periodic_check(ctx, now);
			if (flow->is_stale(now)) {
				stale_flows.push_back(flow);
			}
		}
		for (Flow* flow : stale_flows) {
			flow->destroy(ctx);
		}
	};

	do_gc(ctx->ipv4_tcp_flows_by_key);
	do_gc(ctx->ipv4_udp_flows_by_key);
	do_gc(ctx->ipv4_icmp_flows_by_key);
	do_gc(ctx->ipv6_tcp_flows_by_key);
	do_gc(ctx->ipv6_udp_flows_by_key);
	do_gc(ctx->ipv6_icmp_flows_by_key);
}

static void handle_host_events(Context* ctx, int fd, uint32_t events) {
	auto it_listener = ctx->host_listener_fd_to_rule.find(fd);
	if (it_listener != ctx->host_listener_fd_to_rule.end()) {
		if (it_listener->second.proto == NSTUN_PROTO_TCP) {
			handle_host_tcp_accept(ctx, fd, it_listener->second);
		} else if (it_listener->second.proto == NSTUN_PROTO_UDP) {
			handle_host_udp_accept(ctx, fd, it_listener->second);
		}
		return;
	}

	auto it = ctx->flows_by_fd.find(fd);
	if (it != ctx->flows_by_fd.end()) {
		it->second->handle_host_event(ctx, fd, events);
		return;
	}

	/* Stale event: fd was already destroyed while processing an earlier event
	 * in the same epoll_wait batch. Just skip it silently. */
	LOG_D("Stale epoll event for fd %d (already closed), skipping", fd);
}

static void networkLoop(Context* ctx) {
	LOG_D("nstun network loop started on tap_fd=%d", ctx->tap_fd);

	defer {
		if (ctx->tap_fd != -1) {
			close(ctx->tap_fd);
			ctx->tap_fd = -1;
		}
		if (ctx->epoll_fd != -1) {
			close(ctx->epoll_fd);
			ctx->epoll_fd = -1;
		}
	};

	struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = ctx->tap_fd}};
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->tap_fd, &ev) == -1) {
		PLOG_E("epoll_ctl(EPOLL_CTL_ADD, tap_fd)");
		return;
	}

	/* TUN frames: 4-byte header + up to NSTUN_MTU bytes of L3 payload */
	static constexpr size_t TUN_FRAME_BUF_SIZE = NSTUN_MTU + 4;
	auto buf = std::make_unique<uint8_t[]>(TUN_FRAME_BUF_SIZE);
	struct epoll_event events[64];
	time_t last_gc = time(NULL);

	while (true) {
		int nfds = epoll_wait(ctx->epoll_fd, events, 64, 1000); /* 1s timeout */
		if (nfds == -1) {
			if (errno == EINTR) continue;
			PLOG_E("epoll_wait");
			break;
		}

		time_t now = time(NULL);
		if (now - last_gc >= 2) {
			garbage_collect(ctx);
			last_gc = now;
		}

		for (int i = 0; i < nfds; ++i) {
			int fd = events[i].data.fd;

			if (fd == ctx->tap_fd) {
				ssize_t n = TEMP_FAILURE_RETRY(
				    read(ctx->tap_fd, buf.get(), TUN_FRAME_BUF_SIZE));
				if (n <= 0) {
					if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
						continue;
					}
					PLOG_E("read(tap_fd) failed or EOF");
					return;
				}
				handle_tun_frame(ctx, buf.get(), n);
			} else {
				handle_host_events(ctx, fd, events[i].events);
			}
		}
	}
}

/*
 * Syscalls the network loop needs: I/O on the TUN fd and on host sockets,
 * epoll, memory management, clocks, and what logging uses. Everything else,
 * including execve(), open() and ptrace(), kills the helper.
 */
static_assert(AF_INET == 2 && AF_INET6 == 10 && PROT_EXEC == 4, "policy constants");
static const char kHelperPolicy[] =
    "POLICY nstun_helper {\n"
    "  ALLOW {\n"
    "    read, write, writev, close,\n"
#if defined(__NR_epoll_wait)
    "    epoll_wait,\n"
#endif
    "    epoll_pwait, epoll_ctl,\n"
    "    socket(domain, type, protocol) { domain == 2 || domain == 10 },\n"
    "    connect, bind, accept4, shutdown,\n"
    "    sendto, recvfrom, recvmmsg,\n"
    "    setsockopt, getsockopt, getsockname,\n"
#if defined(__NR_mmap)
    "    mmap(addr, length, prot) { (prot & 4) == 0 },\n"
#endif
#if defined(__NR_mmap2)
    "    mmap2(addr, length, prot) { (prot & 4) == 0 },\n"
#endif
    "    munmap, mremap, madvise, brk,\n"
#if defined(__NR_time)
    "    time,\n"
#endif
    "    clock_gettime, gettimeofday,\n"
    "    getpid, gettid, getrandom,\n"
    "    rt_sigreturn, exit, exit_group\n"
    "  }\n"
    "}\n"
    "USE nstun_helper DEFAULT KILL_PROCESS\n";

static bool compileHelperPolicy(struct sock_fprog* prog) {
	kafel_ctxt_t kctxt = kafel_ctxt_create();
	kafel_set_input_string(kctxt, kHelperPolicy);
	if (kafel_compile(kctxt, prog) != 0) {
		LOG_E("Could not compile the nstun helper seccomp policy: %s",
		    kafel_error_msg(kctxt));
		kafel_ctxt_destroy(&kctxt);
		return false;
	}
	kafel_ctxt_destroy(&kctxt);
	return true;
}

/*
 * Closes every inherited descriptor the loop doesn't use: the supervisor's own
 * sockets, other jails' descriptors and so on. stdin, stdout and stderr are
 * pointed at /dev/null, unless one of them is a descriptor the loop needs.
 */
static bool helperCloseFds(const Context* ctx) {
	std::set<int> keep = {ctx->tap_fd, ctx->epoll_fd, logs::logFd()};
	for (const auto& [fd, _] : ctx->host_listener_fd_to_rule) {
		keep.insert(fd);
	}

	int devnull = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR | O_CLOEXEC));
	if (devnull == -1) {
		PLOG_E("open('/dev/null')");
		return false;
	}
	for (int fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
		if (keep.count(fd) == 0 && fd != devnull &&
		    TEMP_FAILURE_RETRY(dup2(devnull, fd)) == -1) {
			PLOG_E("dup2(%d, %d)", devnull, fd);
			return false;
		}
		keep.insert(fd);
	}
	if (devnull > STDERR_FILENO) {
		close(devnull);
	}

	DIR* dir = opendir("/proc/self/fd");
	if (dir == nullptr) {
		PLOG_E("opendir('/proc/self/fd')");
		return false;
	}
	std::vector<int> to_close;
	for (struct dirent* entry; (entry = readdir(dir)) != nullptr;) {
		char* end;
		long fd = strtol(entry->d_name, &end, 10);
		if (end == entry->d_name || *end != '\0' || fd == dirfd(dir)) {
			continue;
		}
		if (keep.count((int)fd) == 0) {
			to_close.push_back((int)fd);
		}
	}
	closedir(dir);
	for (int fd : to_close) {
		close(fd);
	}
	return true;
}

static bool helperDropPrivs(void) {
	/* Needs CAP_SETPCAP, so best effort. With execve() blocked it is a second barrier only. */
	for (unsigned long cap = 0; prctl(PR_CAPBSET_READ, cap, 0UL, 0UL, 0UL) >= 0; cap++) {
		(void)prctl(PR_CAPBSET_DROP, cap, 0UL, 0UL, 0UL);
	}
	(void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL);

	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};
	if (util::syscall(__NR_capset, (uintptr_t)&hdr, (uintptr_t)data) == -1) {
		PLOG_E("capset()");
		return false;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == -1) {
		PLOG_E("prctl(PR_SET_NO_NEW_PRIVS, 1)");
		return false;
	}
	return true;
}

[[noreturn]] static void helperMain(Context* ctx, pid_t supervisor, struct sock_fprog* prog) {
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL) == -1) {
		PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL)");
		_exit(EXIT_FAILURE);
	}
	/* The supervisor may have exited before PR_SET_PDEATHSIG took effect */
	if (getppid() != supervisor) {
		_exit(EXIT_FAILURE);
	}

	/*
	 * Both are set up lazily and may need to open files. Do it now, before the
	 * seccomp policy forbids that. The PRNG state is thread-local, so without a
	 * reseed the helper could start from the supervisor's state.
	 */
	util::rndReseed();
	tzset();

	if (!helperCloseFds(ctx) || !helperDropPrivs()) {
		_exit(EXIT_FAILURE);
	}
	if (util::syscall(__NR_seccomp, (uintptr_t)SECCOMP_SET_MODE_FILTER, 0, (uintptr_t)prog) ==
	    -1) {
		PLOG_E("seccomp(SECCOMP_SET_MODE_FILTER)");
		_exit(EXIT_FAILURE);
	}

	networkLoop(ctx);
	_exit(EXIT_SUCCESS);
}

} /* namespace nstun */

bool nstun_init_child(int sock, nsj_t* nsj) {
	/* Create TUN device. */
	int tap_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (tap_fd < 0) {
		PLOG_E("open(/dev/net/tun)");
		return false;
	}

	bool success = false;
	defer {
		if (!success) {
			close(tap_fd);
		}
	};

	struct ifreq ifr = {};
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* TUN, no packet info */
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());

	if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
		PLOG_E("ioctl(TUNSETIFF)");
		return false;
	}

	/* Configure IP, MAC, UP, route. */
	if (!nstun::configIface(nsj)) {
		LOG_E("nstun::configIface() failed");
		return false;
	}

	/* Send FD to parent */
	if (!util::sendFd(sock, tap_fd)) {
		PLOG_E("util::sendFd(tap_fd)");
		return false;
	}

	success = true;
	close(tap_fd);

	return true;
}

bool nstun_init_parent(int sock, nsj_t* nsj, struct nstun_context_handle** out_handle) {
	if (out_handle == nullptr) {
		LOG_E("nstun_init_parent() requires an output handle");
		return false;
	}
	*out_handle = nullptr;
	auto handle = std::make_unique<nstun_context_handle>();

	int tap_fd = util::recvFd(sock);
	if (tap_fd < 0) {
		LOG_E("Failed to receive TAP fd from child");
		return false;
	}

	LOG_I("nstun initialized successfully, tap_fd=%d", tap_fd);

	std::unique_ptr<nstun::Context> ctx = std::make_unique<nstun::Context>();
	ctx->epoll_fd = -1; /* Not used yet */
	ctx->tap_fd = tap_fd;
	ctx->nsj = nsj;

	auto assign_ip = [](const std::string& str, uint32_t* ip) {
		if (inet_pton(AF_INET, str.c_str(), ip) != 1) {
			LOG_E("Failed to parse IP: %s", str.c_str());
			return false;
		}
		return true;
	};

	if (!nsj->njc.user_net().ip4().empty()) {
		if (!assign_ip(nsj->njc.user_net().ip4(), &ctx->guest_ip4)) {
			close(tap_fd);
			return false;
		}
	}
	if (!nsj->njc.user_net().gw4().empty()) {
		if (!assign_ip(nsj->njc.user_net().gw4(), &ctx->host_ip4)) {
			close(tap_fd);
			return false;
		}
	}

	if (!nsj->njc.user_net().ip6().empty()) {
		if (inet_pton(AF_INET6, nsj->njc.user_net().ip6().c_str(), ctx->guest_ip6) != 1) {
			LOG_E("Cannot convert '%s' into an IPv6 address",
			    nsj->njc.user_net().ip6().c_str());
			close(tap_fd);
			return false;
		}
	}
	if (!nsj->njc.user_net().gw6().empty()) {
		if (inet_pton(AF_INET6, nsj->njc.user_net().gw6().c_str(), ctx->host_ip6) != 1) {
			LOG_E("Cannot convert '%s' into an IPv6 address",
			    nsj->njc.user_net().gw6().c_str());
			close(tap_fd);
			return false;
		}
	}

	ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epoll_fd == -1) {
		PLOG_E("epoll_create1(EPOLL_CLOEXEC)");
		close(ctx->tap_fd);
		return false;
	}
	auto cleanup_and_fail = [&ctx]() -> bool {
		for (auto& [fd, _] : ctx->host_listener_fd_to_rule) {
			close(fd);
		}
		ctx->host_listener_fd_to_rule.clear();
		if (ctx->epoll_fd != -1) {
			close(ctx->epoll_fd);
			ctx->epoll_fd = -1;
		}
		if (ctx->tap_fd != -1) {
			close(ctx->tap_fd);
			ctx->tap_fd = -1;
		}
		return false;
	};

	for (int i = 0; i < nsj->njc.user_net().rule4_size(); i++) {
		const auto& r = nsj->njc.user_net().rule4(i);

		nstun_rule_t nr = {};
		nstun::RuleParseStatus status = nstun::fill_rule_common(r, &nr);
		if (status == nstun::RuleParseStatus::ABORT) return cleanup_and_fail();
		if (status == nstun::RuleParseStatus::IGNORE) continue;

		if (r.has_src_ip()) {
			if (!nstun::parse_ip4_cidr(r.src_ip(), &nr.src_ip4, &nr.src_mask4)) {
				return cleanup_and_fail();
			}
		}
		if (r.has_dst_ip()) {
			if (!nstun::parse_ip4_cidr(r.dst_ip(), &nr.dst_ip4, &nr.dst_mask4)) {
				return cleanup_and_fail();
			}
		}

		if (r.has_redirect_ip() &&
		    inet_pton(AF_INET, r.redirect_ip().c_str(), &nr.redirect_ip4) != 1) {
			LOG_E("Invalid redirect IPv4 address: %s", r.redirect_ip().c_str());
			return cleanup_and_fail();
		}
		nr.redirect_port = r.has_redirect_port() ? r.redirect_port() : 0;

		ctx->rules.push_back(nr);

		if (nr.direction == NSTUN_DIR_HOST_TO_GUEST && nr.action == NSTUN_ACTION_REDIRECT) {
			if (nr.proto != NSTUN_PROTO_TCP && nr.proto != NSTUN_PROTO_UDP) {
				LOG_E("HOST_TO_GUEST REDIRECT only supported for TCP/UDP");
				return cleanup_and_fail();
			}
			if (nr.dport_start == 0) {
				LOG_E("HOST_TO_GUEST REDIRECT requires 'dport' to be specified");
				return cleanup_and_fail();
			}
			for (uint32_t port = nr.dport_start; port <= nr.dport_end; port++) {
				int type = (nr.proto == NSTUN_PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
				int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
				if (fd == -1) {
					PLOG_E("socket(AF_INET) for HOST_TO_GUEST");
					return cleanup_and_fail();
				}

				int opt = 1;
				if (nr.proto == NSTUN_PROTO_TCP) {
					if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt,
						sizeof(opt)) == -1) {
						PLOG_W("setsockopt(TCP_NODELAY)");
					}
				}
				if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ==
				    -1) {
					PLOG_E("setsockopt(SO_REUSEADDR)");
					close(fd);
					return cleanup_and_fail();
				}

				if (nr.proto == NSTUN_PROTO_UDP) {
					if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt,
						sizeof(opt)) == -1) {
						PLOG_E(
						    "setsockopt(IP_PKTINFO) for HOST_TO_GUEST UDP");
						close(fd);
						return cleanup_and_fail();
					}
				}

				struct sockaddr_in addr = INIT_SOCKADDR_IN(AF_INET);
				addr.sin_port = htons(port);
				addr.sin_addr.s_addr = nr.src_ip4;

				if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
					PLOG_E("bind() for HOST_TO_GUEST on port %u", port);
					close(fd);
					return cleanup_and_fail();
				}

				if (nr.proto == NSTUN_PROTO_TCP) {
					if (listen(fd, SOMAXCONN) == -1) {
						PLOG_E(
						    "listen() for HOST_TO_GUEST on port %u", port);
						close(fd);
						return cleanup_and_fail();
					}
				}

				struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
				if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for HOST_TO_GUEST");
					close(fd);
					return cleanup_and_fail();
				}

				ctx->host_listener_fd_to_rule[fd] = nr;
				LOG_I(
				    "Listening on host port %u for inbound %s redirection to guest",
				    port, (nr.proto == NSTUN_PROTO_TCP) ? "TCP" : "UDP");
			}
		}
	}

	/* Process IPv6 rules - same NstunRule message, but src_ip4/dst_ip4 parsed as IPv6 */
	for (int i = 0; i < nsj->njc.user_net().rule6_size(); i++) {
		const auto& r = nsj->njc.user_net().rule6(i);

		nstun_rule_t nr = {};
		nr.is_ipv6 = true;
		nstun::RuleParseStatus status = nstun::fill_rule_common(r, &nr);
		if (status == nstun::RuleParseStatus::ABORT) return cleanup_and_fail();
		if (status == nstun::RuleParseStatus::IGNORE) continue;

		if (r.has_src_ip()) {
			if (!nstun::parse_ip6_cidr(r.src_ip(), nr.src_ip6, nr.src_mask6)) {
				return cleanup_and_fail();
			}
		}
		if (r.has_dst_ip()) {
			if (!nstun::parse_ip6_cidr(r.dst_ip(), nr.dst_ip6, nr.dst_mask6)) {
				return cleanup_and_fail();
			}
		}

		if (r.has_redirect_ip()) {
			if (nr.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
			    nr.action == NSTUN_ACTION_ENCAP_CONNECT) {
				/* Proxy is always IPv4 */
				if (inet_pton(AF_INET, r.redirect_ip().c_str(), &nr.redirect_ip4) !=
				    1) {
					LOG_E("Invalid redirect IPv4 address: %s",
					    r.redirect_ip().c_str());
					return cleanup_and_fail();
				}
			} else {
				/* REDIRECT: target is IPv6 */
				if (inet_pton(AF_INET6, r.redirect_ip().c_str(), nr.redirect_ip6) !=
				    1) {
					LOG_E("Invalid redirect IPv6 address: %s",
					    r.redirect_ip().c_str());
					return cleanup_and_fail();
				}
			}
		}
		nr.redirect_port = r.has_redirect_port() ? r.redirect_port() : 0;

		ctx->rules.push_back(nr);

		if (nr.direction == NSTUN_DIR_HOST_TO_GUEST && nr.action == NSTUN_ACTION_REDIRECT) {
			if (nr.proto != NSTUN_PROTO_TCP && nr.proto != NSTUN_PROTO_UDP) {
				LOG_E("HOST_TO_GUEST REDIRECT only supported for TCP/UDP");
				return cleanup_and_fail();
			}
			if (nr.dport_start == 0) {
				LOG_E("HOST_TO_GUEST REDIRECT requires 'dport' to be specified");
				return cleanup_and_fail();
			}
			for (uint32_t port = nr.dport_start; port <= nr.dport_end; port++) {
				int type = (nr.proto == NSTUN_PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
				int fd = socket(AF_INET6, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
				if (fd == -1) {
					PLOG_E("socket(AF_INET6) for HOST_TO_GUEST");
					return cleanup_and_fail();
				}

				int opt = 1;
				if (nr.proto == NSTUN_PROTO_TCP) {
					if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt,
						sizeof(opt)) == -1) {
						PLOG_W("setsockopt(TCP_NODELAY)");
					}
				}
				if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ==
				    -1) {
					PLOG_E("setsockopt(SO_REUSEADDR)");
					close(fd);
					return cleanup_and_fail();
				}
				if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) ==
				    -1) {
					PLOG_E("setsockopt(IPV6_V6ONLY)");
					close(fd);
					return cleanup_and_fail();
				}

				if (nr.proto == NSTUN_PROTO_UDP) {
					if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt,
						sizeof(opt)) == -1) {
						PLOG_E("setsockopt(IPV6_RECVPKTINFO) for "
						       "HOST_TO_GUEST UDP6");
						close(fd);
						return cleanup_and_fail();
					}
				}

				struct sockaddr_in6 addr = INIT_SOCKADDR_IN6(AF_INET6);
				addr.sin6_port = htons(port);
				memcpy(addr.sin6_addr.s6_addr, nr.src_ip6, sizeof(nr.src_ip6));

				if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
					PLOG_E("bind() for HOST_TO_GUEST IPv6 on port %u", port);
					close(fd);
					return cleanup_and_fail();
				}

				if (nr.proto == NSTUN_PROTO_TCP) {
					if (listen(fd, SOMAXCONN) == -1) {
						PLOG_E("listen() for HOST_TO_GUEST IPv6 on port %u",
						    port);
						close(fd);
						return cleanup_and_fail();
					}
				}

				struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
				if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for HOST_TO_GUEST IPv6");
					close(fd);
					return cleanup_and_fail();
				}

				ctx->host_listener_fd_to_rule[fd] = nr;
				LOG_I("Listening on host IPv6 port %u for inbound %s redirection "
				      "to guest",
				    port, (nr.proto == NSTUN_PROTO_TCP) ? "TCP" : "UDP");
			}
		}
	}

	struct sock_fprog prog = {};
	if (!nstun::compileHelperPolicy(&prog)) {
		return cleanup_and_fail();
	}
	defer {
		free(prog.filter);
	};

	/* Run the network loop in a separate, confined process */
	pid_t supervisor = getpid();
	pid_t helper = fork();
	if (helper == -1) {
		PLOG_E("fork()");
		return cleanup_and_fail();
	}
	if (helper == 0) {
		nstun::helperMain(ctx.get(), supervisor, &prog);
	}
	LOG_D("Started nstun helper process %d", (int)helper);

	/* The helper owns the TUN fd, the epoll fd and the listeners now */
	close(ctx->tap_fd);
	close(ctx->epoll_fd);
	/* ~Context() closes the supervisor's copies of the listeners */

	handle->helper_pid = helper;
	*out_handle = handle.release();

	return true;
}

void nstun_destroy_parent(struct nstun_context_handle* handle) {
	if (handle == nullptr) {
		return;
	}

	if (handle->helper_pid > 0) {
		kill(handle->helper_pid, SIGKILL);
		while (waitpid(handle->helper_pid, nullptr, 0) == -1 && errno == EINTR);
	}
	delete handle;
}

pid_t nstun_helper_pid(const struct nstun_context_handle* handle) {
	return handle == nullptr ? -1 : handle->helper_pid;
}

void nstun_helper_reaped(struct nstun_context_handle* handle) {
	if (handle != nullptr) {
		handle->helper_pid = -1;
	}
}
