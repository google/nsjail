#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "encap.h"
#include "icmp.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tun.h"

namespace nstun {

static const char* udp_state_to_str(UdpSocks5State state) {
	struct {
		const uint64_t state;
		const char* const name;
	} static const state_names[] = {
	    NS_VALSTR_STRUCT(UDP_S5_ESTABLISHED),
	    NS_VALSTR_STRUCT(UDP_S5_GREETING),
	    NS_VALSTR_STRUCT(UDP_S5_ASSOCIATE),
	    NS_VALSTR_STRUCT(UDP_S5_TCP_CONNECTING),
	};

	for (const auto& entry : state_names) {
		if (entry.state == static_cast<uint64_t>(state)) {
			return entry.name;
		}
	}
	static thread_local char unknown_buf[32];
	snprintf(unknown_buf, sizeof(unknown_buf), "UNKNOWN(%llu)",
	    static_cast<unsigned long long>(state));
	return unknown_buf;
}

/* UDP idle timeouts (seconds) */
static constexpr time_t UDP_TIMEOUT_ESTABLISHED = 60;
static constexpr time_t UDP_TIMEOUT_CONNECTING = 5; /* SOCKS5 TCP setup */
static UdpFlow* find_ipv4_udp_flow(Context* ctx, const FlowKey4& key4) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		UdpFlow& flow = ctx->c_ipv4_udp_flows[i];
		if (flow.header.active) {
			if (!flow.header.is_ipv6 &&
			    memcmp(&flow.header.key4, &key4, sizeof(key4)) == 0) {
				flow.header.last_active = time(nullptr);
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv4_udp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static UdpFlow* find_ipv6_udp_flow(Context* ctx, const FlowKey6& key6) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; ++i) {
		UdpFlow& flow = ctx->c_ipv6_udp_flows[i];
		if (flow.header.active) {
			if (memcmp(&flow.header.key6, &key6, sizeof(key6)) == 0) {
				flow.header.last_active = time(nullptr);
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv6_udp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static void init_udp_flow_zero(UdpFlow* flow) {
	*flow = UdpFlow{};
	flow->header.type = FlowType::UDP;
	flow->header.host_fd = -1;
	flow->tcp_fd = -1;
}

static UdpFlow* alloc_udp_flow(UdpFlow* flows, size_t max_flows) {
	for (size_t i = 0; i < max_flows; ++i) {
		UdpFlow& flow = flows[i];
		if (!flow.header.active) {
			init_udp_flow_zero(&flow);
			flow.header.active = true;
			return &flow;
		}
	}
	return nullptr;
}

static UdpFlow* alloc_ipv4_udp_flow(Context* ctx) {
	return alloc_udp_flow(ctx->c_ipv4_udp_flows, NSTUN_MAX_FLOWS);
}

static UdpFlow* alloc_ipv6_udp_flow(Context* ctx) {
	return alloc_udp_flow(ctx->c_ipv6_udp_flows, NSTUN_MAX_FLOWS);
}

static void prepare_recvmmsg(Context* ctx) {
	for (int i = 0; i < VLEN; ++i) {
		ctx->recvmmsg_msgs[i].msg_hdr.msg_namelen = sizeof(ctx->recvmmsg_addrs[i]);
		ctx->recvmmsg_msgs[i].msg_hdr.msg_controllen = 0;
	}
}

void udp_destroy_flow(Context* ctx, UdpFlow* flow) {
	if (flow->header.is_ipv6) {
		LOG_D("GC: stale UDP flow (IPv6, sport=%u, socks5=%d)",
		    ntohs(flow->header.key6.sport), flow->use_socks5 ? 1 : 0);
	} else {
		LOG_D("GC: stale UDP flow (sport=%u, socks5=%d)", ntohs(flow->header.key4.sport),
		    flow->use_socks5 ? 1 : 0);
	}

	if (flow->header.host_fd != -1 && !flow->host_fd_is_listener) {
		monitor::removeFd(flow->header.host_fd);
		close(flow->header.host_fd);
		set_udp_flow_by_fd(ctx, flow->header.host_fd, nullptr);
		flow->header.host_fd = -1;
	}
	if (flow->tcp_fd != -1) {
		monitor::removeFd(flow->tcp_fd);
		close(flow->tcp_fd);
		set_udp_flow_by_fd(ctx, flow->tcp_fd, nullptr);
		flow->tcp_fd = -1;
	}
	if (flow->header.is_ipv6) {
		flow->header.active = false;
		ctx->num_c_ipv6_udp_flows--;
	} else {
		flow->header.active = false;
		ctx->num_c_ipv4_udp_flows--;
	}
}

static bool udp_send_packet4(Context* ctx, uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t dport, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("udp_send_packet4: data length too large");
		return false;
	}

	uint8_t header_buf[sizeof(ip4_hdr) + sizeof(udp_hdr)];

	ip4_hdr ip;
	udp_hdr udp;
	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));

	/* IPv4 */
	ip4_set_ihl_version(&ip, 4, sizeof(ip4_hdr) / 4);
	ip.tos = 0;
	ip.tot_len = htons(sizeof(ip4_hdr) + sizeof(udp_hdr) + len);
	ip.id = 0;
	ip.frag_off = 0;
	ip.ttl = 64;
	ip.protocol = IPPROTO_UDP;
	ip.saddr = saddr;
	ip.daddr = daddr;
	ip.check = 0;
	ip.check = compute_checksum(&ip, sizeof(ip4_hdr));

	/* UDP */
	udp.source = sport;
	udp.dest = dport;
	udp.len = htons(sizeof(udp_hdr) + len);
	udp.check = 0;

	pseudo_hdr4 phdr = {
	    .saddr = saddr,
	    .daddr = daddr,
	    .zero = 0,
	    .protocol = IPPROTO_UDP,
	    .len = htons(sizeof(udp_hdr) + len),
	};

	/* Seed check field with pseudo-header sum only; kernel adds L4 header + payload */
	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	udp.check = (uint16_t)sum;
	if (udp.check == 0) {
		udp.check = 0xFFFF;
	}

	memcpy(header_buf, &ip, sizeof(ip));
	memcpy(header_buf + sizeof(ip), &udp, sizeof(udp));

	virtio_net_hdr vh = {};
	vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	vh.csum_start = sizeof(ip4_hdr);
	vh.csum_offset = offsetof(udp_hdr, check);

	return send_to_guest_v(ctx, &vh, header_buf, sizeof(header_buf), data, len);
}

/* Forward declare for use in handle_host_udp */
static bool udp_send_packet6(Context* ctx, const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport, const uint8_t* data, size_t len);

static void udp_push_to_guest(Context* ctx, UdpFlow* flow, const uint8_t* data, size_t data_len,
    const struct sockaddr_storage* src_addr_storage) {
	if (flow->header.is_ipv6) {
		uint8_t saddr6[IPV6_ADDR_LEN];
		uint8_t daddr6[IPV6_ADDR_LEN];
		uint16_t sport, dport;

		memcpy(daddr6, flow->header.key6.saddr6, sizeof(daddr6));
		dport = flow->header.key6.sport;

		if (flow->header.is_redirected || flow->use_socks5) {
			memcpy(saddr6, flow->header.orig_dest_ip6, sizeof(saddr6));
			sport = htons(flow->header.orig_dest_port);
		} else if (src_addr_storage) {
			struct sockaddr_in6 src6;
			memcpy(&src6, src_addr_storage, sizeof(src6));
			memcpy(saddr6, &src6.sin6_addr, sizeof(saddr6));
			sport = src6.sin6_port;
		} else {
			return;
		}

		if (!udp_send_packet6(ctx, saddr6, daddr6, sport, dport, data, data_len)) {
			LOG_W("udp_push_to_guest: failed to send packet to guest");
		}
	} else {
		uint32_t saddr, daddr;
		uint16_t sport, dport;

		daddr = flow->header.key4.saddr4;
		dport = flow->header.key4.sport;

		if (flow->header.is_redirected || flow->use_socks5) {
			saddr = flow->header.orig_dest_ip4;
			sport = htons(flow->header.orig_dest_port);
		} else if (src_addr_storage) {
			struct sockaddr_in src_addr;
			memcpy(&src_addr, src_addr_storage, sizeof(src_addr));
			saddr = src_addr.sin_addr.s_addr;
			sport = src_addr.sin_port;
		} else {
			return;
		}

		if (!udp_send_packet4(ctx, saddr, daddr, sport, dport, data, data_len)) {
			LOG_W("udp_push_to_guest: failed to send packet to guest");
		}
	}
}

typedef void (*UdpControlHandler)(Context* ctx, UdpFlow* flow, uint32_t events);

struct UdpStateHandlers {
	UdpControlHandler on_host_control;
};

static void handle_udp_tcp_connecting(Context* ctx, UdpFlow* flow, uint32_t events) {
	int fd = flow->tcp_fd;
	if (!(events & EPOLLOUT)) {
		LOG_W("connect() to SOCKS5 proxy failed (no EPOLLOUT, events=0x%x)", events);
		udp_destroy_flow(ctx, flow);
		return;
	}
	int err = 0;
	socklen_t errlen = sizeof(err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
	if (err != 0) {
		char err_buf[256];
		LOG_W("connect() to SOCKS5 proxy failed: %s",
		    strerror_r(err, err_buf, sizeof(err_buf)));
		udp_destroy_flow(ctx, flow);
		return;
	}
	if (!monitor::modFd(fd, EPOLLIN | EPOLLERR | EPOLLHUP)) {
		PLOG_E("monitor::modFd() failed");
		udp_destroy_flow(ctx, flow);
		return;
	}

	if (flow->use_socks5) {
		flow->state = UDP_S5_GREETING;
		LOG_D("Flow %d: UDP_S5_TCP_CONNECTING -> UDP_S5_GREETING", flow->tcp_fd);
		if (nstun::send_socks5_greeting(fd) < 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
	}
}

static void handle_udp_socks5_greeting(Context* ctx, UdpFlow* flow, uint32_t events) {
	int fd = flow->tcp_fd;
	socks5_auth_reply reply;
	ssize_t n = TEMP_FAILURE_RETRY(recv(fd, &reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT));
	if (n <= 0) {
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}
		if (n == 0) {
			LOG_W("SOCKS5 proxy closed connection during greeting");
		} else {
			PLOG_W("recv() from SOCKS5 proxy failed during greeting");
		}
		udp_destroy_flow(ctx, flow);
		return;
	}
	if (n < (ssize_t)sizeof(reply)) {
		return;
	}
	if (TEMP_FAILURE_RETRY(recv(fd, &reply, sizeof(reply), MSG_DONTWAIT)) !=
	    (ssize_t)sizeof(reply)) {
		udp_destroy_flow(ctx, flow);
		return;
	}
	uint8_t reply_buf[sizeof(reply)];
	memcpy(reply_buf, &reply, sizeof(reply));
	if (!nstun::parse_socks5_auth_reply(reply_buf, sizeof(reply_buf))) {
		udp_destroy_flow(ctx, flow);
		return;
	}
	flow->state = UDP_S5_ASSOCIATE;
	LOG_D("Flow %d: UDP_S5_GREETING -> UDP_S5_ASSOCIATE", flow->tcp_fd);
	if (nstun::send_socks5_udp_associate(fd) < 0) {
		udp_destroy_flow(ctx, flow);
		return;
	}
}

static void handle_udp_socks5_associate(Context* ctx, UdpFlow* flow, uint32_t events) {
	int fd = flow->tcp_fd;
	socks5_req req = {};
	ssize_t n = TEMP_FAILURE_RETRY(recv(fd, &req, sizeof(req), MSG_PEEK | MSG_DONTWAIT));
	if (n <= 0) {
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}
		if (n == 0) {
			LOG_W("SOCKS5 proxy closed connection during associate");
		} else {
			PLOG_W("recv() from SOCKS5 proxy failed during associate");
		}
		udp_destroy_flow(ctx, flow);
		return;
	}
	if (n < 4) { /* SOCKS5 reply header is 4 bytes (VER, REP, RSV, ATYP) */
		return;
	}
	if (req.ver != SOCKS5_VERSION || req.cmd != SOCKS5_REP_SUCCESS) {
		udp_destroy_flow(ctx, flow);
		return;
	}

	size_t expected_len = 0;

	switch (req.atyp) {
	case SOCKS5_ATYP_IPV4:
		expected_len = sizeof(socks5_req); /* header+ip4+port */
		break;
	case SOCKS5_ATYP_IPV6:
		expected_len = sizeof(socks5_req6); /* header+ip6+port */
		break;
	case SOCKS5_ATYP_DOMAIN:
		n = TEMP_FAILURE_RETRY(recv(fd, &ctx->udp_socks5_buf, sizeof(ctx->udp_socks5_buf),
		    MSG_PEEK | MSG_DONTWAIT));
		if (n < (ssize_t)sizeof(socks5_req_domain)) {
			return;
		}
		socks5_req_domain dreq;
		memcpy(&dreq, &ctx->udp_socks5_buf, sizeof(dreq));
		expected_len = sizeof(socks5_req_domain) + dreq.domain_len + 2;
		break;
	default:
		udp_destroy_flow(ctx, flow);
		return;
	}

	if ((size_t)n < expected_len) {
		return;
	}

	if ((size_t)TEMP_FAILURE_RETRY(
		recv(fd, &ctx->udp_socks5_buf, expected_len, MSG_DONTWAIT)) != expected_len) {
		udp_destroy_flow(ctx, flow);
		return;
	}

	nstun::Socks5Reply res;
	if (!nstun::parse_socks5_connect_reply(ctx->udp_socks5_buf.data, expected_len, &res)) {
		udp_destroy_flow(ctx, flow);
		return;
	}

	if (res.atyp == SOCKS5_ATYP_IPV4) {
		memcpy(&flow->bnd_ip, &res.bind_ip4, sizeof(flow->bnd_ip));
		memcpy(&flow->bnd_port, &res.bind_port, sizeof(flow->bnd_port));
	} else {
		LOG_E("SOCKS5 UDP proxy returned unsupported address type");
		udp_destroy_flow(ctx, flow);
		return;
	}

	int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (udp_fd == -1) {
		udp_destroy_flow(ctx, flow);
		return;
	}
	struct sockaddr_in bind_addr = INIT_SOCKADDR_IN(AF_INET);
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	bind_addr.sin_port = 0;
	if (bind(udp_fd, reinterpret_cast<struct sockaddr*>(&bind_addr), sizeof(bind_addr)) == -1) {
		close(udp_fd);
		udp_destroy_flow(ctx, flow);
		return;
	}
	if (!monitor::addFd(udp_fd, EPOLLIN, host_callback, ctx)) {
		close(udp_fd);
		udp_destroy_flow(ctx, flow);
		return;
	}
	flow->header.host_fd = udp_fd;
	set_udp_flow_by_fd(ctx, udp_fd, flow);
	flow->state = UDP_S5_ESTABLISHED;
	LOG_D("Flow %d: UDP_S5_ASSOCIATE -> UDP_S5_ESTABLISHED", flow->tcp_fd);

	while (flow->c_tx_queue_count > 0) {
		size_t idx = flow->c_tx_queue_head;
		const uint8_t* pkt_data = flow->c_tx_queue[idx].data;
		size_t pkt_len = flow->c_tx_queue[idx].len;

		flow->c_tx_queue_head = (flow->c_tx_queue_head + 1) % UDP_QUEUE_MAX_PACKETS;
		flow->c_tx_queue_count--;

		struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
		dest_addr.sin_addr.s_addr = flow->bnd_ip;
		dest_addr.sin_port = flow->bnd_port;

		if (flow->header.is_ipv6) {
			socks5_udp_hdr6 hdr;
			hdr.rsv = 0;
			hdr.frag = 0;
			hdr.atyp = SOCKS5_ATYP_IPV6;
			memcpy(hdr.dst_ip6, flow->header.orig_dest_ip6, sizeof(hdr.dst_ip6));
			hdr.dst_port = htons(flow->header.orig_dest_port);

			struct iovec iov[2];
			iov[0].iov_base = &hdr;
			iov[0].iov_len = sizeof(hdr);
			iov[1].iov_base = const_cast<uint8_t*>(pkt_data);
			iov[1].iov_len = pkt_len;

			struct msghdr msg = {};
			msg.msg_name = &dest_addr;
			msg.msg_namelen = sizeof(dest_addr);
			msg.msg_iov = iov;
			msg.msg_iovlen = 2;

			if (sendmsg(flow->header.host_fd, &msg, MSG_NOSIGNAL) == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				}
				PLOG_E("sendmsg(fd=%d) SOCKS5 UDP failed", flow->header.host_fd);
			}
		} else {
			socks5_udp_hdr hdr;
			hdr.rsv = 0;
			hdr.frag = 0;
			hdr.atyp = SOCKS5_ATYP_IPV4;
			hdr.dst_ip4 = flow->header.orig_dest_ip4;
			hdr.dst_port = htons(flow->header.orig_dest_port);

			struct iovec iov[2];
			iov[0].iov_base = &hdr;
			iov[0].iov_len = sizeof(hdr);
			iov[1].iov_base = const_cast<uint8_t*>(pkt_data);
			iov[1].iov_len = pkt_len;

			struct msghdr msg = {};
			msg.msg_name = &dest_addr;
			msg.msg_namelen = sizeof(dest_addr);
			msg.msg_iov = iov;
			msg.msg_iovlen = 2;

			if (sendmsg(flow->header.host_fd, &msg, MSG_NOSIGNAL) == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				}
				PLOG_E("sendmsg(fd=%d) SOCKS5 UDP failed", flow->header.host_fd);
			}
		}
	}
	flow->c_tx_queue_head = 0;
	flow->c_tx_queue_tail = 0;
	flow->c_tx_queue_count = 0;
}

static void handle_udp_established(Context* ctx, UdpFlow* flow, uint32_t events) {
	int fd = flow->tcp_fd;
	/* Detect SOCKS5 TCP control channel death */
	if (events & (EPOLLERR | EPOLLHUP | EPOLLIN)) {
		uint8_t buf[1];
		ssize_t n = TEMP_FAILURE_RETRY(recv(fd, buf, 1, MSG_PEEK | MSG_DONTWAIT));
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return;
			}
			LOG_D("SOCKS5 TCP control channel died, destroying UDP flow");
			udp_destroy_flow(ctx, flow);
		}
	}
}

static const UdpStateHandlers kUdpStateTable[] = {
    [UDP_S5_ESTABLISHED] = {handle_udp_established},
    [UDP_S5_GREETING] = {handle_udp_socks5_greeting},
    [UDP_S5_ASSOCIATE] = {handle_udp_socks5_associate},
    [UDP_S5_TCP_CONNECTING] = {handle_udp_tcp_connecting},
};

static void handle_host_udp_control(Context* ctx, UdpFlow* flow, uint32_t events) {
	flow->header.last_active = time(nullptr);

	size_t state_idx = static_cast<size_t>(flow->state);
	if (state_idx >= sizeof(kUdpStateTable) / sizeof(kUdpStateTable[0])) {
		LOG_F("Invalid UDP SOCKS5 state: %zu", state_idx);
		abort();
	}

	kUdpStateTable[state_idx].on_host_control(ctx, flow, events);
}

static bool udp_setup_socks5_control(
    Context* ctx, UdpFlow* flow, uint32_t proxy_ip4, uint16_t proxy_port) {
	int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (tcp_fd == -1) {
		return false;
	}
	if (tcp_fd >= static_cast<int>(NSTUN_MAX_FDS)) {
		LOG_E("FD limit reached (tcp_fd=%d)", tcp_fd);
		close(tcp_fd);
		return false;
	}

	bool fd_success = false;
	defer {
		if (!fd_success) {
			close(tcp_fd);
		}
	};

	if (!monitor::addFd(tcp_fd, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, host_callback, ctx)) {
		return false;
	}

	struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
	dest_addr.sin_addr.s_addr = proxy_ip4;
	dest_addr.sin_port = htons(proxy_port);
	int ret =
	    connect(tcp_fd, reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr));
	if (ret == -1 && errno != EINPROGRESS && errno != EINTR) {
		PLOG_W("connect() to SOCKS5 proxy failed");
		monitor::removeFd(tcp_fd);
		return false;
	}
	fd_success = true;

	flow->tcp_fd = tcp_fd;
	flow->state = UDP_S5_TCP_CONNECTING;
	LOG_D("Flow %d: initialized to UDP_S5_TCP_CONNECTING", tcp_fd);
	return true;
}

static int create_and_bind_udp_socket(Context* ctx) {
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		PLOG_E("socket(AF_INET, SOCK_DGRAM) for UDP flow failed");
		return -1;
	}
	if (fd >= static_cast<int>(NSTUN_MAX_FDS)) {
		LOG_E("FD limit reached (fd=%d)", fd);
		close(fd);
		return -1;
	}

	bool success = false;
	defer {
		if (!success) close(fd);
	};

	struct sockaddr_in bind_addr = INIT_SOCKADDR_IN(AF_INET);
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	bind_addr.sin_port = 0;
	if (bind(fd, reinterpret_cast<struct sockaddr*>(&bind_addr), sizeof(bind_addr)) == -1) {
		PLOG_E("bind() UDP host socket failed");
		return -1;
	}

	if (!monitor::addFd(fd, EPOLLIN, host_callback, ctx)) {
		PLOG_E("monitor::addFd(UDP host socket) failed");
		return -1;
	}

	success = true;
	return fd;
}

static UdpFlow* udp_create_flow4(Context* ctx, const FlowKey4& key4, const RuleResult& rule,
    const ip4_hdr* ip, uint16_t dest_port, uint16_t guest_port) {
	UdpFlow* flow = alloc_ipv4_udp_flow(ctx);
	if (!flow) {
		LOG_E("Failed to allocate Flow (table full)");
		return nullptr;
	}
	init_udp_flow_zero(flow);
	flow->header.active = true;
	flow->header.type = FlowType::UDP;
	ctx->num_c_ipv4_udp_flows++;

	flow->header.host_fd = -1;
	flow->tcp_fd = -1;
	flow->header.is_ipv6 = false;
	flow->header.key4 = key4;
	flow->header.last_active = time(nullptr);
	flow->header.is_redirected = (rule.redirect_ip4 != 0 || rule.redirect_port != 0);
	flow->header.orig_dest_ip4 = ip->daddr;
	flow->header.orig_dest_port = dest_port;
	flow->use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5);
	flow->header.redirect_ip4 = rule.redirect_ip4;
	flow->header.redirect_port = rule.redirect_port;

	if (flow->use_socks5) {
		if (!udp_setup_socks5_control(ctx, flow, rule.redirect_ip4, rule.redirect_port)) {
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		int tcp_fd = flow->tcp_fd;
		set_udp_flow_by_fd(ctx, tcp_fd, flow);
		LOG_D("Created UDP Proxy flow (socks5=%d) for guest port %u -> tcp fd %d%s",
		    flow->use_socks5 ? 1 : 0, guest_port, tcp_fd,
		    flow->header.is_redirected ? " [redirected]" : "");
	} else {
		int fd = create_and_bind_udp_socket(ctx);
		if (fd == -1) {
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		flow->header.host_fd = fd;
		flow->state = UDP_S5_ESTABLISHED;
		LOG_D("Flow %d: initialized to UDP_S5_ESTABLISHED", fd);
		set_udp_flow_by_fd(ctx, fd, flow);
		LOG_D("Created UDP flow for guest port %u -> fd %d%s", guest_port, fd,
		    flow->header.is_redirected ? " [redirected]" : "");
	}
	return flow;
}

static bool udp_enqueue_packet(
    UdpFlow* flow, const uint8_t* data, size_t data_len, const char* proto_str) {
	if (data_len > UDP_QUEUE_PACKET_MAX) {
		LOG_D("%s proxy queue dropping oversized packet (%zu > %zu bytes)", proto_str,
		    data_len, UDP_QUEUE_PACKET_MAX);
		return false;
	}
	size_t idx = flow->c_tx_queue_tail;
	memcpy(flow->c_tx_queue[idx].data, data, data_len);
	flow->c_tx_queue[idx].len = data_len;

	flow->c_tx_queue_tail = (flow->c_tx_queue_tail + 1) % UDP_QUEUE_MAX_PACKETS;

	if (flow->c_tx_queue_count < UDP_QUEUE_MAX_PACKETS) {
		flow->c_tx_queue_count++;
	} else {
		/* Overwrite oldest, advance head */
		flow->c_tx_queue_head = (flow->c_tx_queue_head + 1) % UDP_QUEUE_MAX_PACKETS;
	}
	return true;
}

void handle_udp4_impl(
    Context* ctx, const ip4_hdr* ip, const uint8_t* payload_data, size_t payload_size) {
	if (payload_size < sizeof(udp_hdr)) {
		return;
	}

	udp_hdr udp;
	memcpy(&udp, payload_data, sizeof(udp));
	uint16_t guest_port = ntohs(udp.source);
	uint16_t dest_port = ntohs(udp.dest);

	/* Validate UDP checksum (optional for IPv4 when field is 0; skip if offloaded) */
	if (udp.check != 0 && !(ctx->last_vnet_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)) {
		pseudo_hdr4 phdr = {
		    .saddr = ip->saddr,
		    .daddr = ip->daddr,
		    .zero = 0,
		    .protocol = IPPROTO_UDP,
		    .len = htons(payload_size),
		};
		uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
		csum = compute_checksum_part(payload_data, payload_size, csum);
		if (finalize_checksum(csum) != 0) {
			LOG_D("Invalid IPv4 UDP checksum, dropping");
			return;
		}
	}

	FlowKey4 key4 = {ip->saddr, ip->daddr, udp.source, udp.dest};

	/* Find or create flow */
	UdpFlow* flow = find_ipv4_udp_flow(ctx, key4);
	if (!flow) {
		RuleResult rule = evaluate_rules4(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_UDP,
		    ip->saddr, ip->daddr, guest_port, dest_port);

		switch (rule.action) {
		case NSTUN_ACTION_DROP:
			LOG_D("UDP flow %u -> %s:%u dropped by policy", guest_port,
			    ip4_to_string(ip->daddr).c_str(), dest_port);
			return;
		case NSTUN_ACTION_REJECT:
			LOG_D("UDP flow %u -> %s:%u rejected by policy", guest_port,
			    ip4_to_string(ip->daddr).c_str(), dest_port);
			send_icmp4_error(
			    ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
			return;
		case NSTUN_ACTION_ENCAP_CONNECT:
			LOG_W(
			    "HTTP CONNECT proxy not supported for UDP, dropping packet to port %u",
			    dest_port);
			return;
		default:
			break;
		}

		if (ctx->num_c_ipv4_udp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of UDP flows reached, dropping");
			send_icmp4_error(
			    ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
			return;
		}
		flow = udp_create_flow4(ctx, key4, rule, ip, dest_port, guest_port);
		if (!flow) {
			send_icmp4_error(
			    ctx, ip, ntohs(ip->tot_len), ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
			return;
		}
	}

	const uint8_t* data = payload_data + sizeof(udp_hdr);
	size_t data_len = payload_size - sizeof(udp_hdr);

	if (flow->use_socks5 && flow->state != UDP_S5_ESTABLISHED) {
		/* Cap queued packet size to prevent memory exhaustion:
		 * NSTUN_MAX_FLOWS * 50 packets * UDP_QUEUE_PACKET_MAX = ~75MB worst case */
		if (!udp_enqueue_packet(flow, data, data_len, "UDP")) {
			return;
		}
		return;
	}

	struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);

	if (flow->use_socks5) {
		dest_addr.sin_addr.s_addr = flow->bnd_ip;
		dest_addr.sin_port = flow->bnd_port;

		socks5_udp_hdr hdr;
		hdr.rsv = 0;
		hdr.frag = 0;
		hdr.atyp = SOCKS5_ATYP_IPV4;
		hdr.dst_ip4 = flow->header.orig_dest_ip4;
		hdr.dst_port = htons(flow->header.orig_dest_port);

		struct iovec iov[2];
		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(hdr);
		iov[1].iov_base = const_cast<uint8_t*>(data);
		iov[1].iov_len = data_len;

		struct msghdr msg = {};
		msg.msg_name = &dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		if (sendmsg(flow->header.host_fd, &msg, MSG_NOSIGNAL) == -1) {
			PLOG_E("sendmsg(fd=%d) SOCKS5 UDP failed", flow->header.host_fd);
		}
	} else {
		/* Use the redirect destination stored in the flow at creation time.
		 * Do NOT re-evaluate the rule - it may yield different results
		 * for packets on an already-established flow. */
		if (flow->header.redirect_ip4 && flow->header.redirect_port) {
			dest_addr.sin_addr.s_addr = flow->header.redirect_ip4;
			dest_addr.sin_port = htons(flow->header.redirect_port);
		} else {
			dest_addr.sin_addr.s_addr = ip->daddr;
			dest_addr.sin_port = htons(dest_port);
		}
		if (sendto(flow->header.host_fd, data, data_len, MSG_NOSIGNAL,
			reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr)) == -1) {
			PLOG_E("sendto(fd=%d) UDP failed", flow->header.host_fd);
		}
	}
}

void handle_udp4(Context* ctx, const ip4_hdr* ip, const uint8_t* data, size_t len) {
	handle_udp4_impl(ctx, ip, data, len);
}

static bool strip_socks5_udp_header(const uint8_t** data_ptr, size_t* data_len) {
	if (*data_len < sizeof(socks5_udp_hdr)) {
		return false;
	}
	socks5_udp_hdr hdr;
	memcpy(&hdr, *data_ptr, sizeof(hdr));
	if (hdr.rsv != 0 || hdr.frag != 0) {
		return false;
	}

	size_t header_len = 0;
	switch (hdr.atyp) {
	case SOCKS5_ATYP_IPV4:
		header_len = sizeof(socks5_udp_hdr);
		break;
	case SOCKS5_ATYP_IPV6:
		header_len = sizeof(socks5_udp_hdr6);
		break;
	case SOCKS5_ATYP_DOMAIN:
		if (*data_len < sizeof(socks5_udp_hdr_domain)) {
			return false;
		}
		socks5_udp_hdr_domain dhdr;
		memcpy(&dhdr, *data_ptr, sizeof(dhdr));
		header_len = sizeof(socks5_udp_hdr_domain) + dhdr.domain_len + 2;
		break;
	default:
		return false;
	}

	if (*data_len < header_len) {
		return false;
	}

	*data_ptr += header_len;
	*data_len -= header_len;
	return true;
}

static void handle_host_udp(Context* ctx, UdpFlow* flow) {
	int fd = flow->header.host_fd;
	flow->header.last_active = time(nullptr);

	prepare_recvmmsg(ctx);

	int retval =
	    TEMP_FAILURE_RETRY(recvmmsg(fd, ctx->recvmmsg_msgs, VLEN, MSG_DONTWAIT, nullptr));
	if (retval == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		PLOG_E("recvmmsg(fd=%d) failed", fd);
		udp_destroy_flow(ctx, flow);
		return;
	}
	if (retval == 0) {
		return;
	}

	for (int i = 0; i < retval; ++i) {
		const uint8_t* data_ptr = ctx->recvmmsg_bufs[i];
		size_t data_len = ctx->recvmmsg_msgs[i].msg_len;
		struct sockaddr_storage* src_addr_storage = &ctx->recvmmsg_addrs[i];

		if (flow->use_socks5) {
			if (!strip_socks5_udp_header(&data_ptr, &data_len)) {
				continue;
			}
		}

		udp_push_to_guest(ctx, flow, data_ptr, data_len, src_addr_storage);
	}
}

static void handle_host_udp_accept_pkt6(Context* ctx, int listen_fd, const nstun_rule_t& rule,
    uint16_t listen_port, struct sockaddr_storage* client_ss, uint8_t* data_ptr, size_t data_len) {
	struct sockaddr_in6 client6;
	memcpy(&client6, client_ss, sizeof(client6));

	uint8_t client_ip6[IPV6_ADDR_LEN];
	memcpy(client_ip6, &client6.sin6_addr, sizeof(client_ip6));
	if (IN6_IS_ADDR_LOOPBACK(&client6.sin6_addr)) {
		memcpy(client_ip6, ctx->host_ip6, sizeof(client_ip6));
	}

	FlowKey6 key6 = {};
	bool has_redirect_ip6 =
	    !IN6_IS_ADDR_UNSPECIFIED(reinterpret_cast<const struct in6_addr*>(rule.redirect_ip6));
	if (has_redirect_ip6) {
		memcpy(key6.saddr6, rule.redirect_ip6, sizeof(key6.saddr6));
	} else {
		memcpy(key6.saddr6, ctx->guest_ip6, sizeof(key6.saddr6));
	}
	memcpy(key6.daddr6, client_ip6, sizeof(key6.daddr6));
	key6.sport = rule.redirect_port ? htons(rule.redirect_port) : listen_port;
	key6.dport = client6.sin6_port;

	UdpFlow* flow = find_ipv6_udp_flow(ctx, key6);
	if (!flow) {
		if (ctx->num_c_ipv6_udp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of IPv6 UDP flows reached, dropping");
			return;
		}
		flow = alloc_ipv6_udp_flow(ctx);
		if (!flow) {
			LOG_E("Failed to allocate Flow (table full)");
			return;
		}
		init_udp_flow_zero(flow);
		flow->header.active = true;
		flow->header.type = FlowType::UDP;
		flow->header.is_ipv6 = true;
		flow->header.host_fd = listen_fd;
		flow->header.key6 = key6;
		flow->header.last_active = time(nullptr);
		flow->header.is_redirected = true;
		flow->use_socks5 = false;
		flow->state = UDP_S5_ESTABLISHED;
		LOG_D("Flow %d: initialized to UDP_S5_ESTABLISHED (inbound IPv6)", listen_fd);
		flow->host_fd_is_listener = true;
		ctx->num_c_ipv6_udp_flows++;
	}

	if (!udp_send_packet6(
		ctx, key6.daddr6, key6.saddr6, key6.dport, key6.sport, data_ptr, data_len)) {
		LOG_W("handle_host_udp_accept_pkt6: failed to send packet to guest");
	}
}

static void handle_host_udp_accept_pkt4(Context* ctx, int listen_fd, const nstun_rule_t& rule,
    uint16_t listen_port, struct sockaddr_storage* client_ss, uint8_t* data_ptr, size_t data_len) {
	struct sockaddr_in client4;
	memcpy(&client4, client_ss, sizeof(client4));

	uint32_t client_ip = client4.sin_addr.s_addr;
	if (client_ip == htonl(INADDR_LOOPBACK)) {
		client_ip = ctx->host_ip4; /* Prevent martian drops in guest */
	}

	FlowKey4 key4 = {
	    .saddr4 = rule.redirect_ip4 ? rule.redirect_ip4 : ctx->guest_ip4,
	    .daddr4 = client_ip,
	    .sport = rule.redirect_port ? htons(rule.redirect_port) : listen_port,
	    .dport = client4.sin_port,
	};

	UdpFlow* flow = find_ipv4_udp_flow(ctx, key4);
	if (!flow) {
		if (ctx->num_c_ipv4_udp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of UDP flows reached, dropping");
			return;
		}
		flow = alloc_ipv4_udp_flow(ctx);
		if (!flow) {
			LOG_E("Failed to allocate Flow (table full)");
			return;
		}
		init_udp_flow_zero(flow);
		flow->header.active = true;
		flow->header.type = FlowType::UDP;
		flow->header.is_ipv6 = false;
		flow->header.host_fd = listen_fd;
		flow->header.key4 = key4;
		flow->header.last_active = time(nullptr);
		flow->header.is_redirected = true;
		flow->use_socks5 = false;
		flow->state = UDP_S5_ESTABLISHED;
		LOG_D("Flow %d: initialized to UDP_S5_ESTABLISHED (inbound IPv4)", listen_fd);
		flow->host_fd_is_listener = true;
		ctx->num_c_ipv4_udp_flows++;
	}

	if (!udp_send_packet4(
		ctx, key4.daddr4, key4.saddr4, key4.dport, key4.sport, data_ptr, data_len)) {
		LOG_W("handle_host_udp_accept_pkt4: failed to send packet to guest");
	}
}

void handle_host_udp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_udp_accept listen_fd=%d", listen_fd);

	uint16_t listen_port = 0;
	struct sockaddr_storage listen_addr = {};
	socklen_t listen_addrlen = sizeof(listen_addr);
	if (getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&listen_addr),
		&listen_addrlen) == -1) {
		PLOG_E("getsockname(listen_fd=%d) failed", listen_fd);
		return;
	}
	if (rule.is_ipv6) {
		listen_port = reinterpret_cast<struct sockaddr_in6*>(&listen_addr)->sin6_port;
	} else {
		listen_port = reinterpret_cast<struct sockaddr_in*>(&listen_addr)->sin_port;
	}

	prepare_recvmmsg(ctx);

	int retval = TEMP_FAILURE_RETRY(
	    recvmmsg(listen_fd, ctx->recvmmsg_msgs, VLEN, MSG_DONTWAIT, nullptr));
	if (retval == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_E("recvmmsg(fd=%d) failed", listen_fd);
		}
		return;
	}
	if (retval == 0) {
		return;
	}

	for (int i = 0; i < retval; ++i) {
		uint8_t* data_ptr = ctx->recvmmsg_bufs[i];
		size_t data_len = ctx->recvmmsg_msgs[i].msg_len;
		struct sockaddr_storage* client_ss = &ctx->recvmmsg_addrs[i];

		if (rule.is_ipv6) {
			handle_host_udp_accept_pkt6(
			    ctx, listen_fd, rule, listen_port, client_ss, data_ptr, data_len);
		} else {
			handle_host_udp_accept_pkt4(
			    ctx, listen_fd, rule, listen_port, client_ss, data_ptr, data_len);
		}
	}
}

static bool udp_send_packet6(Context* ctx, const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("udp_send_packet6: data length too large");
		return false;
	}

	uint8_t header_buf[sizeof(ip6_hdr) + sizeof(udp_hdr)];

	ip6_hdr r_ip;
	udp_hdr r_udp;
	memset(&r_ip, 0, sizeof(r_ip));
	memset(&r_udp, 0, sizeof(r_udp));

	/* IPv6 */
	r_ip.vtf = htonl(0x60000000); /* Version 6 */
	r_ip.payload_len = htons(sizeof(udp_hdr) + len);
	r_ip.next_header = IPPROTO_UDP;
	r_ip.hop_limit = 64;
	memcpy(r_ip.saddr, saddr, sizeof(r_ip.saddr));
	memcpy(r_ip.daddr, daddr, sizeof(r_ip.daddr));

	/* UDP */
	r_udp.source = sport;
	r_udp.dest = dport;
	r_udp.len = htons(sizeof(udp_hdr) + len);
	r_udp.check = 0;

	/* 40-byte IPv6 pseudo header */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(sizeof(udp_hdr) + len);
	phdr.next_header = IPPROTO_UDP;
	memcpy(phdr.saddr, saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, daddr, sizeof(phdr.daddr));

	/* Seed check field with pseudo-header sum only; kernel adds L4 header + payload */
	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	r_udp.check = (uint16_t)sum;
	if (r_udp.check == 0) {
		r_udp.check = 0xFFFF;
	}

	memcpy(header_buf, &r_ip, sizeof(r_ip));
	memcpy(header_buf + sizeof(ip6_hdr), &r_udp, sizeof(r_udp));

	virtio_net_hdr vh = {};
	vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	vh.csum_start = sizeof(ip6_hdr);
	vh.csum_offset = offsetof(udp_hdr, check);

	return send_to_guest_v(ctx, &vh, header_buf, sizeof(header_buf), data, len);
}

static UdpFlow* udp_create_flow6(Context* ctx, const FlowKey6& key6, const RuleResult& rule,
    const ip6_hdr* ip, uint16_t dest_port, uint16_t guest_port) {
	UdpFlow* flow = alloc_ipv6_udp_flow(ctx);
	if (!flow) {
		LOG_E("Failed to allocate Flow (table full)");
		return nullptr;
	}
	init_udp_flow_zero(flow);
	flow->header.active = true;
	flow->header.type = FlowType::UDP;
	ctx->num_c_ipv6_udp_flows++;

	flow->header.host_fd = -1;
	flow->tcp_fd = -1;
	flow->header.is_ipv6 = true;
	flow->header.key6 = key6;
	flow->header.last_active = time(nullptr);
	flow->header.is_redirected = (rule.has_redirect_ip6 || rule.redirect_port != 0);
	memcpy(flow->header.orig_dest_ip6, ip->daddr, sizeof(flow->header.orig_dest_ip6));
	flow->header.orig_dest_port = dest_port;
	flow->use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5);
	if (rule.has_redirect_ip6) {
		memcpy(flow->header.redirect_ip6, rule.redirect_ip6,
		    sizeof(flow->header.redirect_ip6));
	}
	flow->header.redirect_ip4 = rule.redirect_ip4; /* SOCKS5 proxy is IPv4 */
	flow->header.redirect_port = rule.redirect_port;

	if (flow->use_socks5) {
		if (!udp_setup_socks5_control(ctx, flow, rule.redirect_ip4, rule.redirect_port)) {
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		int tcp_fd = flow->tcp_fd;
		set_udp_flow_by_fd(ctx, tcp_fd, flow);
		LOG_D("Created IPv6 UDP Proxy flow (socks5=%d) for guest port %u -> tcp fd %d%s",
		    flow->use_socks5 ? 1 : 0, guest_port, tcp_fd,
		    flow->header.is_redirected ? " [redirected]" : "");
	} else {
		int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket(AF_INET6, SOCK_DGRAM) for IPv6 UDP flow failed");
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		if (fd >= static_cast<int>(NSTUN_MAX_FDS)) {
			LOG_E("FD limit reached (fd=%d)", fd);
			close(fd);
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		bool fd_success = false;
		defer {
			if (!fd_success) close(fd);
		};

		struct sockaddr_in6 bind_addr = INIT_SOCKADDR_IN6(AF_INET6);
		if (bind(fd, reinterpret_cast<struct sockaddr*>(&bind_addr), sizeof(bind_addr)) ==
		    -1) {
			PLOG_E("bind() IPv6 UDP host socket failed");
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}

		if (!monitor::addFd(fd, EPOLLIN, host_callback, ctx)) {
			PLOG_E("monitor::addFd(IPv6 UDP host socket) failed");
			udp_destroy_flow(ctx, flow);
			return nullptr;
		}
		fd_success = true;

		flow->header.host_fd = fd;
		flow->state = UDP_S5_ESTABLISHED;
		LOG_D("Flow %d: initialized to UDP_S5_ESTABLISHED (IPv6)", fd);
		set_udp_flow_by_fd(ctx, fd, flow);
		LOG_D("Created IPv6 UDP flow for guest port %u -> fd %d%s", guest_port, fd,
		    flow->header.is_redirected ? " [redirected]" : "");
	}
	return flow;
}

void handle_udp6_impl(
    Context* ctx, const ip6_hdr* ip, const uint8_t* payload_data, size_t payload_size) {
	if (payload_size < sizeof(udp_hdr)) {
		return;
	}

	udp_hdr udp;
	memcpy(&udp, payload_data, sizeof(udp));
	uint16_t guest_port = ntohs(udp.source);
	uint16_t dest_port = ntohs(udp.dest);

	/* Validate UDP checksum (mandatory for IPv6; skip if offloaded) */
	if (!(ctx->last_vnet_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)) {
		pseudo_hdr6 phdr = {};
		phdr.len = htonl(payload_size);
		phdr.next_header = IPPROTO_UDP;
		memcpy(phdr.saddr, ip->saddr, sizeof(phdr.saddr));
		memcpy(phdr.daddr, ip->daddr, sizeof(phdr.daddr));
		uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
		csum = compute_checksum_part(payload_data, payload_size, csum);
		if (finalize_checksum(csum) != 0) {
			LOG_D("Invalid IPv6 UDP checksum, dropping");
			return;
		}
	}

	FlowKey6 key6 = {};
	memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
	memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
	key6.sport = udp.source;
	key6.dport = udp.dest;

	UdpFlow* flow = find_ipv6_udp_flow(ctx, key6);
	if (!flow) {
		RuleResult rule = evaluate_rules6(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_UDP,
		    ip->saddr, ip->daddr, guest_port, dest_port);

		switch (rule.action) {
		case NSTUN_ACTION_DROP:
			LOG_D("IPv6 UDP flow %u -> %u dropped by policy", guest_port, dest_port);
			return;
		case NSTUN_ACTION_REJECT:
			LOG_D("IPv6 UDP flow %u -> %u rejected by policy", guest_port, dest_port);
			send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + payload_size, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT);
			return;
		case NSTUN_ACTION_ENCAP_CONNECT:
			LOG_W(
			    "HTTP CONNECT proxy not supported for UDP, dropping packet to port %u",
			    dest_port);
			return;
		default:
			break;
		}

		if (ctx->num_c_ipv6_udp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of IPv6 UDP flows reached, dropping");
			send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + payload_size, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT);
			return;
		}

		flow = udp_create_flow6(ctx, key6, rule, ip, dest_port, guest_port);
		if (!flow) {
			send_icmp6_error(ctx, ip, sizeof(ip6_hdr) + payload_size, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT);
			return;
		}
	}

	const uint8_t* data = payload_data + sizeof(udp_hdr);
	size_t data_len = payload_size - sizeof(udp_hdr);

	if (flow->use_socks5 && flow->state != UDP_S5_ESTABLISHED) {
		/* Cap queued packet size to prevent memory exhaustion */
		if (!udp_enqueue_packet(flow, data, data_len, "IPv6 UDP")) {
			return;
		}
		return;
	}

	struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);

	if (flow->use_socks5) {
		struct sockaddr_in dest_addr4 = INIT_SOCKADDR_IN(AF_INET);
		dest_addr4.sin_addr.s_addr = flow->bnd_ip;
		dest_addr4.sin_port = flow->bnd_port;

		socks5_udp_hdr6 hdr;
		hdr.rsv = 0;
		hdr.frag = 0;
		hdr.atyp = SOCKS5_ATYP_IPV6;
		memcpy(hdr.dst_ip6, flow->header.orig_dest_ip6, sizeof(hdr.dst_ip6));
		hdr.dst_port = htons(flow->header.orig_dest_port);

		struct iovec iov[2];
		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(hdr);
		iov[1].iov_base = const_cast<uint8_t*>(data);
		iov[1].iov_len = data_len;

		struct msghdr msg = {};
		msg.msg_name = &dest_addr4;
		msg.msg_namelen = sizeof(dest_addr4);
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		if (sendmsg(flow->header.host_fd, &msg, MSG_NOSIGNAL) == -1) {
			PLOG_E("sendmsg(fd=%d) SOCKS5 UDP failed", flow->header.host_fd);
		}
	} else {
		/* Use the redirect destination stored in the flow at creation time.
		 * Do NOT re-evaluate the rule for packets on an existing flow. */
		struct in6_addr addr;
		memcpy(&addr, flow->header.redirect_ip6, sizeof(addr));
		bool has_redirect = !IN6_IS_ADDR_UNSPECIFIED(&addr);
		if (has_redirect && flow->header.redirect_port) {
			memcpy(&dest_addr.sin6_addr, flow->header.redirect_ip6,
			    sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(flow->header.redirect_port);
		} else {
			memcpy(&dest_addr.sin6_addr, ip->daddr, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(dest_port);
		}
		if (sendto(flow->header.host_fd, data, data_len, MSG_NOSIGNAL,
			reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr)) == -1) {
			PLOG_E("sendto(fd=%d) UDP failed", flow->header.host_fd);
		}
	}
}

void handle_udp6(Context* ctx, const ip6_hdr* ip, const uint8_t* data, size_t len) {
	handle_udp6_impl(ctx, ip, data, len);
}

void handle_host_udp_event(Context* ctx, UdpFlow* flow, int fd, uint32_t events) {
	UdpFlow* udp_flow = flow;
	if (fd == udp_flow->header.host_fd) {
		handle_host_udp(ctx, udp_flow);
	} else if (fd == udp_flow->tcp_fd) {
		handle_host_udp_control(ctx, flow, events);
	} else {
		LOG_E("handle_host_udp_event: unknown fd=%d (host_fd=%d, tcp_fd=%d)", fd,
		    udp_flow->header.host_fd, udp_flow->tcp_fd);
	}
}

bool is_stale_udp(const UdpFlow* flow, time_t now) {
	time_t timeout = UDP_TIMEOUT_ESTABLISHED;
	if (flow->use_socks5 && flow->state != UDP_S5_ESTABLISHED) {
		timeout = UDP_TIMEOUT_CONNECTING;
	}
	return (now - flow->header.last_active) > timeout;
}

} /* namespace nstun */
