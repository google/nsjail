#include "nstun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
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
#include "tcp.h"
#include "tun.h"
#include "udp.h"
#include "util.h"

namespace nstun {

Context::~Context() {
	for (auto& pair : udp_flows_by_key) {
		if (pair.second->host_fd != -1) close(pair.second->host_fd);
		if (pair.second->tcp_fd != -1) close(pair.second->tcp_fd);
		delete pair.second;
	}
	for (auto& pair : tcp_flows_by_key) {
		if (pair.second->host_fd != -1) close(pair.second->host_fd);
		delete pair.second;
	}
	for (auto& pair : icmp_flows_by_key) {
		if (pair.second->host_fd != -1) close(pair.second->host_fd);
		delete pair.second;
	}
}

RuleResult evaluate_rules(Context* ctx, nstun_proto_t proto, uint32_t src_ip, uint32_t dst_ip,
    uint16_t sport, uint16_t dport) {
	for (const auto& r : ctx->rules) {
		if (r.proto != NSTUN_PROTO_ANY && r.proto != proto) continue;

		if (r.src_ip != 0 && (src_ip & r.src_mask) != (r.src_ip & r.src_mask)) continue;
		if (r.dst_ip != 0 && (dst_ip & r.dst_mask) != (r.dst_ip & r.dst_mask)) continue;

		if (r.sport_start != 0 && (sport < r.sport_start || sport > r.sport_end)) continue;
		if (r.dport_start != 0 && (dport < r.dport_start || dport > r.dport_end)) continue;

		RuleResult res = {r.action, 0, 0};
		if (r.action == NSTUN_ACTION_REDIRECT || r.action == NSTUN_ACTION_ENCAP_SOCKS5) {
			res.redirect_ip = r.redirect_ip;
			res.redirect_port = r.redirect_port;
		}
		return res;
	}
	return {NSTUN_ACTION_ALLOW, 0, 0}; /* Default allow */
}

static void garbage_collect(Context* ctx) {
	time_t now = time(NULL);

	/* Collect TCP flows */
	std::vector<TcpFlow*> stale_tcp;
	for (auto const& [key, flow] : ctx->tcp_flows_by_key) {
		time_t timeout = 3600; /* default 1 hour for established */
		if (flow->state == TcpState::SYN_SENT || flow->state == TcpState::SOCKS5_INIT ||
		    flow->state == TcpState::SOCKS5_CONNECTING) {
			timeout = 5;
		} else if (flow->state == TcpState::CLOSE_WAIT ||
			   flow->state == TcpState::LAST_ACK ||
			   flow->state == TcpState::TIME_WAIT) {
			timeout = 10;
		}
		if (now - flow->last_active > timeout) {
			stale_tcp.push_back(flow);
		}
	}
	for (TcpFlow* flow : stale_tcp) {
		LOG_D("Garbage collecting stale TCP flow %u", ntohs(flow->key.sport));
		tcp_destroy_flow(ctx, flow);
	}

	/* Collect UDP flows */
	std::vector<UdpFlow*> stale_udp;
	for (auto const& [key, flow] : ctx->udp_flows_by_key) {
		if (now - flow->last_active > 60) {
			stale_udp.push_back(flow);
		}
	}
	for (UdpFlow* flow : stale_udp) {
		LOG_D("Garbage collecting stale UDP flow %u", ntohs(flow->key.sport));
		udp_destroy_flow(ctx, flow);
	}

	/* Collect ICMP flows */
	std::vector<IcmpFlow*> stale_icmp;
	for (auto const& [key, flow] : ctx->icmp_flows_by_key) {
		if (now - flow->last_active > 10) {
			stale_icmp.push_back(flow);
		}
	}
	for (IcmpFlow* flow : stale_icmp) {
		LOG_D("Garbage collecting stale ICMP flow %u", ntohs(flow->key.id));
		icmp_destroy_flow(ctx, flow);
	}
}

static void handle_host_events(Context* ctx, int fd, uint32_t events) {
	if (ctx->udp_flows_by_host_fd.find(fd) != ctx->udp_flows_by_host_fd.end()) {
		handle_host_udp(ctx, fd);
		return;
	}
	if (ctx->udp_flows_by_tcp_fd.find(fd) != ctx->udp_flows_by_tcp_fd.end()) {
		handle_host_udp_control(ctx, fd, events);
		return;
	}
	if (ctx->tcp_flows_by_host_fd.find(fd) != ctx->tcp_flows_by_host_fd.end()) {
		handle_host_tcp(ctx, fd, events);
		return;
	}
	if (ctx->icmp_flows_by_host_fd.find(fd) != ctx->icmp_flows_by_host_fd.end()) {
		handle_host_icmp(ctx, fd);
		return;
	}

	LOG_W("Unknown fd %d in epoll", fd);
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
	close(fd);
}

static void networkLoop(Context* ctx) {
	LOG_I("nstun network loop started on tap_fd=%d", ctx->tap_fd);

	ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epoll_fd == -1) {
		PLOG_E("epoll_create1(EPOLL_CLOEXEC)");
		return;
	}

	defer {
		close(ctx->tap_fd);
		close(ctx->epoll_fd);
		delete ctx;
	};

	struct epoll_event ev = {};
	ev.events = EPOLLIN;
	ev.data.fd = ctx->tap_fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->tap_fd, &ev) == -1) {
		PLOG_E("epoll_ctl(EPOLL_CTL_ADD, tap_fd)");
		return;
	}

	uint8_t buf[65536];
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
		if (now - last_gc >= 1) {
			garbage_collect(ctx);
			last_gc = now;
		}

		for (int i = 0; i < nfds; ++i) {
			int fd = events[i].data.fd;

			if (fd == ctx->tap_fd) {
				ssize_t n = TEMP_FAILURE_RETRY(read(ctx->tap_fd, buf, sizeof(buf)));
				if (n <= 0) {
					if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
						continue;
					}
					PLOG_E("read(tap_fd) failed or EOF");
					return;
				}
				handle_tun_frame(ctx, buf, n);
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

	nstun::Context* ctx = new nstun::Context{};
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
		assign_ip(nsj->njc.user_net().ip4(), &ctx->guest_ip);
	}
	if (!nsj->njc.user_net().gw4().empty()) {
		assign_ip(nsj->njc.user_net().gw4(), &ctx->host_ip);
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

	for (int i = 0; i < nsj->njc.user_net().rule4_size(); i++) {
		const auto& r = nsj->njc.user_net().rule4(i);

		if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_SOCKS5 &&
		    r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_ICMP) {
			LOG_E("SOCKS5 encapsulation is not supported for ICMP/ICMPv6");
			delete ctx;
			return false;
		}

		nstun_rule_t nr = {};
		if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_DROP) {
			nr.action = NSTUN_ACTION_DROP;
		} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_REJECT) {
			nr.action = NSTUN_ACTION_REJECT;
		} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_ALLOW) {
			nr.action = NSTUN_ACTION_ALLOW;
		} else if (r.action() == nsjail::NsJailConfig_UserNet_NstunRule_Action_REDIRECT) {
			nr.action = NSTUN_ACTION_REDIRECT;
		} else if (r.action() ==
			   nsjail::NsJailConfig_UserNet_NstunRule_Action_ENCAP_SOCKS5) {
			nr.action = NSTUN_ACTION_ENCAP_SOCKS5;
		} else {
			continue;
		}

		if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_TCP) {
			nr.proto = NSTUN_PROTO_TCP;
		} else if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_UDP) {
			nr.proto = NSTUN_PROTO_UDP;
		} else if (r.proto() == nsjail::NsJailConfig_UserNet_NstunRule_Protocol_ICMP) {
			nr.proto = NSTUN_PROTO_ICMP;
		} else {
			nr.proto = NSTUN_PROTO_ANY;
		}

		nr.sport_start = r.has_sport() ? r.sport() : 0;
		nr.sport_end = r.has_sport_end() ? r.sport_end() : nr.sport_start;
		nr.dport_start = r.has_dport() ? r.dport() : 0;
		nr.dport_end = r.has_dport_end() ? r.dport_end() : nr.dport_start;

		if (r.has_src_ip()) {
			parse_ip(r.src_ip(), &nr.src_ip, &nr.src_mask);
		}
		if (r.has_dst_ip()) {
			parse_ip(r.dst_ip(), &nr.dst_ip, &nr.dst_mask);
		}

		if (r.has_redirect_ip()) {
			struct nl_addr* addr;
			if (nl_addr_parse(r.redirect_ip().c_str(), AF_INET, &addr) == 0) {
				if (nl_addr_get_len(addr) == 4) {
					memcpy(&nr.redirect_ip, nl_addr_get_binary_addr(addr), 4);
				}
				nl_addr_put(addr);
			}
			nr.redirect_port = r.has_redirect_port() ? r.redirect_port() : 0;
		}

		ctx->rules.push_back(nr);
	}

	/* Spawn network loop thread */
	std::thread t(nstun::networkLoop, ctx);
	t.detach();

	return true;
}
