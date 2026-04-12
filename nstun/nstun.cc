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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <new>
#include <thread>

#include "core.h"
#include "icmp.h"
#include "iface.h"
#include "ip.h"
#include "logs.h"
#include "macros.h"
#include "monitor.h"
#include "nsjail.h"
#include "policy.h"
#include "tcp.h"
#include "tun.h"
#include "udp.h"
#include "util.h"

namespace nstun {

constexpr int kMaxReadIterations = 16;
constexpr int kMaxPortRange = 1024;

bool icmp_is_stale(const IcmpFlow* flow, time_t now);
void icmp_destroy(Context* ctx, IcmpFlow* flow);
void icmp_handle_host_event(Context* ctx, IcmpFlow* flow, int fd, uint32_t events);

static void contextCleanup(Context* ctx) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		if (ctx->c_ipv4_udp_flows[i].header.active) {
			udp_destroy_flow(ctx, &ctx->c_ipv4_udp_flows[i]);
		}
		if (ctx->c_ipv6_udp_flows[i].header.active) {
			udp_destroy_flow(ctx, &ctx->c_ipv6_udp_flows[i]);
		}
		if (ctx->c_ipv4_tcp_flows[i].header.active) {
			tcp_destroy_flow(ctx, &ctx->c_ipv4_tcp_flows[i]);
		}
		if (ctx->c_ipv6_tcp_flows[i].header.active) {
			tcp_destroy_flow(ctx, &ctx->c_ipv6_tcp_flows[i]);
		}
		if (ctx->c_ipv4_icmp_flows[i].header.active) {
			icmp_destroy(ctx, &ctx->c_ipv4_icmp_flows[i]);
		}
		if (ctx->c_ipv6_icmp_flows[i].header.active) {
			icmp_destroy(ctx, &ctx->c_ipv6_icmp_flows[i]);
		}
	}

	for (size_t i = 0; i < ctx->num_c_host_listener_rules; ++i) {
		monitor::removeFd(ctx->c_host_listener_rules[i].fd);
		close(ctx->c_host_listener_rules[i].fd);
	}
	ctx->num_c_host_listener_rules = 0;
	if (ctx->tap_fd != -1) {
		monitor::removeFd(ctx->tap_fd);
		close(ctx->tap_fd);
	}
}

static void gcDestroyTcpFlow(Context* ctx, TcpFlow* flow) {
	if (flow->header.is_ipv6) {
		LOG_D("GC: stale TCP flow (IPv6, sport=%u, state=%d)",
		    ntohs(flow->header.key6.sport), static_cast<int>(flow->tcp_state));
	} else {
		LOG_D("GC: stale TCP flow (sport=%u, state=%d)", ntohs(flow->header.key4.sport),
		    static_cast<int>(flow->tcp_state));
	}
	tcp_destroy_flow(ctx, flow);
}

static void gcTcpFlows(Context* ctx, TcpFlow* flows, time_t now) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		TcpFlow* flow = &flows[i];
		if (flow->header.active) {
			tcp_periodic_check(ctx, flow, now);
			if (is_stale_tcp(flow, now)) {
				gcDestroyTcpFlow(ctx, flow);
			}
		}
	}
}

static void gcUdpFlows(Context* ctx, UdpFlow* flows, time_t now) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		UdpFlow* flow = &flows[i];
		if (flow->header.active) {
			if (is_stale_udp(flow, now)) {
				udp_destroy_flow(ctx, flow);
			}
		}
	}
}

static void gcIcmpFlows(Context* ctx, IcmpFlow* flows, time_t now) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		IcmpFlow* flow = &flows[i];
		if (flow->header.active) {
			if (icmp_is_stale(flow, now)) {
				icmp_destroy(ctx, flow);
			}
		}
	}
}

static void garbageCollect(Context* ctx) {
	time_t now = time(nullptr);

	gcTcpFlows(ctx, ctx->c_ipv4_tcp_flows, now);
	gcTcpFlows(ctx, ctx->c_ipv6_tcp_flows, now);
	gcUdpFlows(ctx, ctx->c_ipv4_udp_flows, now);
	gcUdpFlows(ctx, ctx->c_ipv6_udp_flows, now);
	gcIcmpFlows(ctx, ctx->c_ipv4_icmp_flows, now);
	gcIcmpFlows(ctx, ctx->c_ipv6_icmp_flows, now);
}

void handle_host_events(Context* ctx, int fd, uint32_t events) {
	LOG_D("handle_host_events: fd=%d, events=0x%x", fd, events);
	for (size_t i = 0; i < ctx->num_c_host_listener_rules; ++i) {
		if (ctx->c_host_listener_rules[i].fd == fd) {
			const nstun_rule_t& rule = ctx->c_host_listener_rules[i].rule;
			switch (rule.proto) {
			case NSTUN_PROTO_TCP:
				handle_host_tcp_accept(ctx, fd, rule);
				break;
			case NSTUN_PROTO_UDP:
				handle_host_udp_accept(ctx, fd, rule);
				break;
			default:
				break;
			}
			return;
		}
	}

	TcpFlow* tcp_flow = get_tcp_flow_by_fd(ctx, fd);
	if (tcp_flow) {
		handle_host_tcp_event(ctx, tcp_flow, fd, events);
		return;
	}
	UdpFlow* udp_flow = get_udp_flow_by_fd(ctx, fd);
	if (udp_flow) {
		handle_host_udp_event(ctx, udp_flow, fd, events);
		return;
	}
	IcmpFlow* icmp_flow = get_icmp_flow_by_fd(ctx, fd);
	if (icmp_flow) {
		icmp_handle_host_event(ctx, icmp_flow, fd, events);
		return;
	}

	if (fd < 0 || fd >= static_cast<int>(NSTUN_MAX_FDS)) {
		LOG_W("FD %d is out of bounds for lookup table (max %zu)", fd, NSTUN_MAX_FDS);
		return;
	}

	/* Stale event: fd was already destroyed while processing an earlier event
	 * in the same epoll_wait batch. Just skip it silently. */
	LOG_D("Stale epoll event for fd %d (already closed), skipping", fd);
}

void host_callback(int fd, uint32_t events, void* data) {
	Context* ctx = static_cast<Context*>(data);
	LOG_D("host_callback: ctx=%p", ctx);
	handle_host_events(ctx, fd, events);
}

} /* namespace nstun */

[[nodiscard]] bool nstun_init_child(int ipc_fd, nsj_t* nsj) {
	/* Create TUN device. */
	int tap_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (tap_fd < 0) {
		PLOG_E("open(/dev/net/tun)");
		return false;
	}
	defer {
		close(tap_fd);
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
	if (!util::sendMsg(ipc_fd, monitor::MSG_TAG_TAP, tap_fd)) {
		PLOG_E("util::sendMsg(tap_fd)");
		return false;
	}

	return true;
}

static void tapCb(int fd, uint32_t /* events */, void* data) {
	nstun::Context* ctx = static_cast<nstun::Context*>(data);

	/* Use a loop to read until EAGAIN, but limit iterations to prevent starvation */
	for (int i = 0; i < nstun::kMaxReadIterations; ++i) {
		ssize_t n = TEMP_FAILURE_RETRY(read(fd, ctx->tun_buf, sizeof(ctx->tun_buf)));
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return;
			}
			PLOG_E("read(tap_fd) failed or EOF, removing FD");
			monitor::removeFd(fd);
			close(fd);
			ctx->tap_fd = -1;
			return;
		}
		handle_tun_frame(ctx, ctx->tun_buf, n);
	}
}

static thread_local nstun::Context* tls_nstun_ctx = nullptr;

void nstun_periodic() {
	if (tls_nstun_ctx) {
		garbageCollect(tls_nstun_ctx);
	}
}

[[nodiscard]] static bool assign_ip(const std::string& str, uint32_t* ip) {
	struct nl_addr* addr;
	if (nl_addr_parse(str.c_str(), AF_INET, &addr) != 0) {
		LOG_E("Failed to parse IP string: %s", str.c_str());
		return false;
	}
	defer {
		nl_addr_put(addr);
	};
	if (nl_addr_get_len(addr) != 4) {
		LOG_E("IP string is not IPv4: %s", str.c_str());
		return false;
	}
	memcpy(ip, nl_addr_get_binary_addr(addr), 4);
	return true;
}

[[nodiscard]] static bool assign_ip6(const std::string& str, uint8_t* ip6) {
	struct nl_addr* addr;
	if (nl_addr_parse(str.c_str(), AF_INET6, &addr) != 0) {
		LOG_E("Failed to parse IPv6 string: %s", str.c_str());
		return false;
	}
	defer {
		nl_addr_put(addr);
	};
	if (nl_addr_get_len(addr) != nstun::IPV6_ADDR_LEN) {
		LOG_E("IP string is not IPv6: %s", str.c_str());
		return false;
	}
	memcpy(ip6, nl_addr_get_binary_addr(addr), nstun::IPV6_ADDR_LEN);
	return true;
}

[[nodiscard]] static bool parse_ip(const std::string& str, uint32_t* ip, uint32_t* mask) {
	struct nl_addr* addr;
	if (nl_addr_parse(str.c_str(), AF_INET, &addr) != 0) {
		LOG_E("Failed to parse IP/CIDR string: %s", str.c_str());
		return false;
	}
	defer {
		nl_addr_put(addr);
	};
	if (nl_addr_get_len(addr) != 4) {
		LOG_E("IP/CIDR string is not IPv4: %s", str.c_str());
		return false;
	}
	memcpy(ip, nl_addr_get_binary_addr(addr), 4);
	int bits = nl_addr_get_prefixlen(addr);
	*mask = (bits == 0) ? 0 : htonl(~((1ULL << (32 - bits)) - 1));
	return true;
}

[[nodiscard]] static bool parse_ip6(const std::string& str, uint8_t* ip6, uint8_t* mask6) {
	struct nl_addr* addr;
	if (nl_addr_parse(str.c_str(), AF_INET6, &addr) != 0) {
		LOG_E("Failed to parse IPv6/CIDR string: %s", str.c_str());
		return false;
	}
	defer {
		nl_addr_put(addr);
	};
	if (nl_addr_get_len(addr) != nstun::IPV6_ADDR_LEN) {
		LOG_E("IPv6/CIDR string is not IPv6: %s", str.c_str());
		return false;
	}
	memcpy(ip6, nl_addr_get_binary_addr(addr), nstun::IPV6_ADDR_LEN);
	int bits = nl_addr_get_prefixlen(addr);
	memset(mask6, 0, nstun::IPV6_ADDR_LEN);
	for (size_t i = 0; i < nstun::IPV6_ADDR_LEN; i++) {
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
	return true;
}

[[nodiscard]] static int create_host_listener(int domain, int type, const struct sockaddr* addr,
    socklen_t addrlen, nstun::Context* ctx, bool is_tcp, uint32_t port) {
	int fd = socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		PLOG_E("socket() for HOST_TO_GUEST");
		return -1;
	}

	int opt = 1;
	if (is_tcp) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
			PLOG_W("setsockopt(TCP_NODELAY)");
		}
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		PLOG_E("setsockopt(SO_REUSEADDR)");
		close(fd);
		return -1;
	}
	if (domain == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1) {
			PLOG_E("setsockopt(IPV6_V6ONLY)");
			close(fd);
			return -1;
		}
	}

	if (bind(fd, addr, addrlen) == -1) {
		PLOG_E("bind() for HOST_TO_GUEST on port %u", port);
		close(fd);
		return -1;
	}

	if (is_tcp) {
		if (listen(fd, SOMAXCONN) == -1) {
			PLOG_E("listen() for HOST_TO_GUEST on port %u", port);
			close(fd);
			return -1;
		}
	}

	if (!monitor::addFd(fd, EPOLLIN, nstun::host_callback, ctx)) {
		LOG_E("monitor::addFd(host_listener_fd) failed");
		close(fd);
		return -1;
	}

	LOG_D("create_host_listener returning fd=%d", fd);
	return fd;
}

[[nodiscard]] static bool setup_host_redirect(nstun::Context* ctx, const nstun_rule_t& nr) {
	if (nr.direction != NSTUN_DIR_HOST_TO_GUEST || nr.action != NSTUN_ACTION_REDIRECT) {
		return true;
	}
	if (nr.proto != NSTUN_PROTO_TCP && nr.proto != NSTUN_PROTO_UDP) {
		LOG_E("HOST_TO_GUEST REDIRECT only supported for TCP/UDP");
		return false;
	}
	if (nr.dport_start == 0) {
		LOG_E("HOST_TO_GUEST REDIRECT requires 'dport' to be specified");
		return false;
	}
	if (nr.dport_end < nr.dport_start) {
		LOG_E("Invalid port range: %u - %u", nr.dport_start, nr.dport_end);
		return false;
	}
	if (nr.dport_end - nr.dport_start >= nstun::kMaxPortRange) {
		LOG_E("Port range too large (%u - %u). Max range is %u.", nr.dport_start,
		    nr.dport_end, nstun::kMaxPortRange);
		return false;
	}

	uint32_t num_ports = nr.dport_end - nr.dport_start + 1;
	if (ctx->num_c_host_listener_rules + num_ports > nstun::NSTUN_MAX_RULES) {
		LOG_E("Not enough space for %u host listener rules (current: %zu, max: %zu)",
		    num_ports, ctx->num_c_host_listener_rules, nstun::NSTUN_MAX_RULES);
		return false;
	}

	int type = (nr.proto == NSTUN_PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	bool is_tcp = (nr.proto == NSTUN_PROTO_TCP);

	for (uint32_t port = nr.dport_start; port <= nr.dport_end; port++) {
		int fd = -1;
		if (nr.is_ipv6) {
			struct sockaddr_in6 addr = INIT_SOCKADDR_IN6(AF_INET6);
			addr.sin6_port = htons(port);
			memcpy(addr.sin6_addr.s6_addr, nr.src_ip6, sizeof(nr.src_ip6));
			fd = create_host_listener(AF_INET6, type, (struct sockaddr*)&addr,
			    sizeof(addr), ctx, is_tcp, port);
		} else {
			struct sockaddr_in addr = INIT_SOCKADDR_IN(AF_INET);
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = nr.src_ip4;
			fd = create_host_listener(AF_INET, type, (struct sockaddr*)&addr,
			    sizeof(addr), ctx, is_tcp, port);
		}
		if (fd == -1) {
			return false;
		}

		ctx->c_host_listener_rules[ctx->num_c_host_listener_rules].fd = fd;
		ctx->c_host_listener_rules[ctx->num_c_host_listener_rules].rule = nr;
		ctx->num_c_host_listener_rules++;

		LOG_I("Listening on host %s port %u for inbound %s redirection to guest",
		    nr.is_ipv6 ? "IPv6" : "IPv4", port,
		    (nr.proto == NSTUN_PROTO_TCP) ? "TCP" : "UDP");
	}
	return true;
}

[[nodiscard]] static bool parse_rules4(nstun::Context* ctx, nsj_t* nsj) {
	for (int i = 0; i < nsj->njc.user_net().rule4_size(); i++) {
		const auto& r = nsj->njc.user_net().rule4(i);

		nstun_rule_t nr = {};
		nstun::RuleParseStatus status = nstun::fill_rule_common(r, &nr);
		if (status == nstun::RuleParseStatus::ABORT) {
			return false;
		}
		if (status == nstun::RuleParseStatus::IGNORE) {
			continue;
		}

		if (r.has_src_ip()) {
			if (!parse_ip(r.src_ip(), &nr.src_ip4, &nr.src_mask4)) {
				return false;
			}
		}
		if (r.has_dst_ip()) {
			if (!parse_ip(r.dst_ip(), &nr.dst_ip4, &nr.dst_mask4)) {
				return false;
			}
		}

		if (r.has_redirect_ip()) {
			if (!assign_ip(r.redirect_ip(), &nr.redirect_ip4)) {
				return false;
			}
		}
		nr.redirect_port = r.has_redirect_port() ? r.redirect_port() : 0;

		if (ctx->c_rules_count >= nstun::NSTUN_MAX_RULES) {
			LOG_E("Too many rules (max %zu)", nstun::NSTUN_MAX_RULES);
			return false;
		}
		ctx->c_rules[ctx->c_rules_count++] = nr;

		if (!setup_host_redirect(ctx, nr)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] static bool parse_rules6(nstun::Context* ctx, nsj_t* nsj) {
	for (int i = 0; i < nsj->njc.user_net().rule6_size(); i++) {
		const auto& r = nsj->njc.user_net().rule6(i);

		nstun_rule_t nr = {};
		nr.is_ipv6 = true;
		nstun::RuleParseStatus status = nstun::fill_rule_common(r, &nr);
		if (status == nstun::RuleParseStatus::ABORT) {
			return false;
		}
		if (status == nstun::RuleParseStatus::IGNORE) {
			continue;
		}

		if (r.has_src_ip()) {
			if (!parse_ip6(r.src_ip(), nr.src_ip6, nr.src_mask6)) {
				return false;
			}
		}
		if (r.has_dst_ip()) {
			if (!parse_ip6(r.dst_ip(), nr.dst_ip6, nr.dst_mask6)) {
				return false;
			}
		}

		if (r.has_redirect_ip()) {
			if (nr.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
			    nr.action == NSTUN_ACTION_ENCAP_CONNECT) {
				/* Proxy is always IPv4 */
				if (!assign_ip(r.redirect_ip(), &nr.redirect_ip4)) {
					return false;
				}
			} else {
				/* REDIRECT: target is IPv6 */
				if (!assign_ip6(r.redirect_ip(), nr.redirect_ip6)) {
					return false;
				}
			}
		}
		nr.redirect_port = r.has_redirect_port() ? r.redirect_port() : 0;

		if (ctx->c_rules_count >= nstun::NSTUN_MAX_RULES) {
			LOG_E("Too many rules (max %zu)", nstun::NSTUN_MAX_RULES);
			return false;
		}
		ctx->c_rules[ctx->c_rules_count++] = nr;

		if (!setup_host_redirect(ctx, nr)) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] static bool setup_ip4(
    const std::string& config_ip, const char* default_ip, uint32_t* out_ip) {
	if (!config_ip.empty()) {
		return assign_ip(config_ip, out_ip);
	}
	if (inet_pton(AF_INET, default_ip, out_ip) != 1) {
		LOG_E("Failed to parse default IP4: %s", default_ip);
		return false;
	}
	return true;
}

[[nodiscard]] static bool setup_ip6(
    const std::string& config_ip, const char* default_ip, uint8_t* out_ip6) {
	if (!config_ip.empty()) {
		if (inet_pton(AF_INET6, config_ip.c_str(), out_ip6) != 1) {
			LOG_E("Cannot convert '%s' into an IPv6 address", config_ip.c_str());
			return false;
		}
		return true;
	}
	if (inet_pton(AF_INET6, default_ip, out_ip6) != 1) {
		LOG_E("Failed to parse default IP6: %s", default_ip);
		return false;
	}
	return true;
}

[[nodiscard]] bool nstun_init_parent(int tap_fd, nsj_t* nsj, pid_t pid) {
	if (tls_nstun_ctx) {
		LOG_W("nstun_init_parent called on already initialized context");
		return false;
	}
	LOG_D("nstun initialized successfully, tap_fd=%d", tap_fd);

	nstun::Context* ctx = new (std::nothrow) nstun::Context();
	if (!ctx) {
		LOG_E("Failed to allocate Context");
		return false;
	}
	LOG_D("nstun_init_parent: allocated ctx=%p", ctx);
	ctx->tap_fd = tap_fd;

	bool success = false;
	defer {
		if (!success) {
			/* Caller (monitorThread) closes tap_fd on failure, so detach it to prevent
			 * double-close */
			ctx->tap_fd = -1;
			contextCleanup(ctx);
			delete ctx;
		}
	};

	if (!setup_ip4(nsj->njc.user_net().ip4(), "192.168.0.2", &ctx->guest_ip4)) {
		return false;
	}
	if (!setup_ip4(nsj->njc.user_net().gw4(), "192.168.0.1", &ctx->host_ip4)) {
		return false;
	}
	if (!setup_ip6(nsj->njc.user_net().ip6(), "fd00::2", ctx->guest_ip6)) {
		return false;
	}
	if (!setup_ip6(nsj->njc.user_net().gw6(), "fd00::1", ctx->host_ip6)) {
		return false;
	}

	if (!parse_rules4(ctx, nsj)) {
		return false;
	}

	if (!parse_rules6(ctx, nsj)) {
		return false;
	}

	/* Register with monitor loop */
	if (!monitor::addFd(ctx->tap_fd, EPOLLIN, tapCb, ctx)) {
		LOG_E("monitor::addFd(tap_fd) failed");
		return false;
	}

	for (int i = 0; i < nstun::VLEN; ++i) {
		ctx->recvmmsg_iovecs[i].iov_base = ctx->recvmmsg_bufs[i];
		ctx->recvmmsg_iovecs[i].iov_len = sizeof(ctx->recvmmsg_bufs[i]);
		ctx->recvmmsg_msgs[i].msg_hdr.msg_iov = &ctx->recvmmsg_iovecs[i];
		ctx->recvmmsg_msgs[i].msg_hdr.msg_iovlen = 1;
		ctx->recvmmsg_msgs[i].msg_hdr.msg_name = &ctx->recvmmsg_addrs[i];
		ctx->recvmmsg_msgs[i].msg_hdr.msg_control = nullptr;
		ctx->recvmmsg_msgs[i].msg_hdr.msg_controllen = 0;
	}
	ctx->recvmmsg_initialized = true;

	tls_nstun_ctx = ctx;
	success = true;
	return true;
}

void nstun_destroy_parent() {
	if (tls_nstun_ctx) {
		contextCleanup(tls_nstun_ctx);
		delete tls_nstun_ctx;
		tls_nstun_ctx = nullptr;
	}
}
