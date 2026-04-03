#include "nstun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netlink/addr.h>
#include <netlink/netlink.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <thread>

#include "core.h"
#include "icmp.h"
#include "iface.h"
#include "ip.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tcp.h"
#include "tun.h"
#include "udp.h"
#include "util.h"

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
		close(ctx->tap_fd);
		close(ctx->epoll_fd);
		delete ctx;
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

bool nstun_init_parent(int sock, nsj_t* nsj) {
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
		struct nl_addr* addr;
		if (nl_addr_parse(str.c_str(), AF_INET, &addr) == 0) {
			if (nl_addr_get_len(addr) == 4) {
				memcpy(ip, nl_addr_get_binary_addr(addr), 4);
			}
			nl_addr_put(addr);
		}
	};

	if (!nsj->njc.user_net().ip4().empty()) {
		assign_ip(nsj->njc.user_net().ip4(), &ctx->guest_ip4);
	}
	if (!nsj->njc.user_net().gw4().empty()) {
		assign_ip(nsj->njc.user_net().gw4(), &ctx->host_ip4);
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

	auto parse_ip = [](const std::string& str, uint32_t* ip, uint32_t* mask) {
		struct nl_addr* addr;
		if (nl_addr_parse(str.c_str(), AF_INET, &addr) == 0) {
			if (nl_addr_get_len(addr) == 4) {
				memcpy(ip, nl_addr_get_binary_addr(addr), 4);
			}
			int bits = nl_addr_get_prefixlen(addr);
			*mask = (bits == 0) ? 0 : htonl(~((1ULL << (32 - bits)) - 1));
			nl_addr_put(addr);
		} else {
			LOG_E("Failed to parse IP/CIDR string: %s", str.c_str());
		}
	};

	auto parse_ip6 = [](const std::string& str, uint8_t* ip6, uint8_t* mask6) {
		struct nl_addr* addr;
		if (nl_addr_parse(str.c_str(), AF_INET6, &addr) == 0) {
			if (nl_addr_get_len(addr) == nstun::IPV6_ADDR_LEN) {
				memcpy(ip6, nl_addr_get_binary_addr(addr), nstun::IPV6_ADDR_LEN);
			}
			int bits = nl_addr_get_prefixlen(addr);
			memset(mask6, 0, nstun::IPV6_ADDR_LEN);
			for (int i = 0; i < (int)nstun::IPV6_ADDR_LEN; i++) {
				if (bits >= 8) {
					mask6[i] = 0xFF;
					bits -= 8;
				} else if (bits > 0) {
					mask6[i] = (uint8_t)(0xFF << (8 - bits));
					bits = 0;
				} else {
					mask6[i] = 0;
				}
			}
			nl_addr_put(addr);
		} else {
			LOG_E("Failed to parse IPv6/CIDR string: %s", str.c_str());
		}
	};

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
		close(ctx->epoll_fd);
		close(ctx->tap_fd);
		return false;
	};

	for (int i = 0; i < nsj->njc.user_net().rule4_size(); i++) {
		const auto& r = nsj->njc.user_net().rule4(i);

		nstun_rule_t nr = {};
		nstun::RuleParseStatus status = nstun::fill_rule_common(r, &nr);
		if (status == nstun::RuleParseStatus::ABORT) return cleanup_and_fail();
		if (status == nstun::RuleParseStatus::IGNORE) continue;

		if (r.has_src_ip()) {
			parse_ip(r.src_ip(), &nr.src_ip4, &nr.src_mask4);
		}
		if (r.has_dst_ip()) {
			parse_ip(r.dst_ip(), &nr.dst_ip4, &nr.dst_mask4);
		}

		if (r.has_redirect_ip()) {
			struct nl_addr* addr;
			if (nl_addr_parse(r.redirect_ip().c_str(), AF_INET, &addr) == 0) {
				if (nl_addr_get_len(addr) == 4) {
					memcpy(&nr.redirect_ip4, nl_addr_get_binary_addr(addr),
					    sizeof(nr.redirect_ip4));
				}
				nl_addr_put(addr);
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
			parse_ip6(r.src_ip(), nr.src_ip6, nr.src_mask6);
		}
		if (r.has_dst_ip()) {
			parse_ip6(r.dst_ip(), nr.dst_ip6, nr.dst_mask6);
		}

		if (r.has_redirect_ip()) {
			if (nr.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
			    nr.action == NSTUN_ACTION_ENCAP_CONNECT) {
				/* Proxy is always IPv4 */
				struct nl_addr* addr;
				if (nl_addr_parse(r.redirect_ip().c_str(), AF_INET, &addr) == 0) {
					if (nl_addr_get_len(addr) == 4) {
						memcpy(&nr.redirect_ip4,
						    nl_addr_get_binary_addr(addr),
						    sizeof(nr.redirect_ip4));
					}
					nl_addr_put(addr);
				}
			} else {
				/* REDIRECT: target is IPv6 */
				struct nl_addr* addr;
				if (nl_addr_parse(r.redirect_ip().c_str(), AF_INET6, &addr) == 0) {
					if (nl_addr_get_len(addr) == 16) {
						memcpy(nr.redirect_ip6,
						    nl_addr_get_binary_addr(addr),
						    sizeof(nr.redirect_ip6));
					}
					nl_addr_put(addr);
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

	/* Spawn network loop thread */
	std::thread t(nstun::networkLoop, ctx.release());
	t.detach();

	return true;
}
