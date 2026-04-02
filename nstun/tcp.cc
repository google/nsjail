#include "tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "encap.h"
#include "logs.h"
#include "macros.h"
#include "policy.h"
#include "tun.h"
#include "util.h"

namespace nstun {

void handle_host_tcp_connected(Context* ctx, TcpFlow* flow, int fd);
void handle_host_tcp_data_eof(Context* ctx, TcpFlow* flow, int fd);

typedef void (*HostEventHandler)(Context* ctx, TcpFlow* flow, int fd);
typedef bool (*GuestPacketHandler)(Context* ctx, TcpFlow* flow, std::span<const uint8_t> data);

struct TcpStateHandlers {
	HostEventHandler on_host_data;
	GuestPacketHandler on_guest_packet;
};

static ProxyMode proxy_mode_from_action(nstun_action_t action) {
	switch (action) {
	case NSTUN_ACTION_ENCAP_SOCKS5:
		return ProxyMode::SOCKS5;
	case NSTUN_ACTION_ENCAP_CONNECT:
		return ProxyMode::HTTP_CONNECT;
	default:
		return ProxyMode::NONE;
	}
}

static constexpr size_t HTTP_PROXY_RESPONSE_MAX = 8192;

/* TCP buffer high-water marks */
static constexpr size_t TCP_TX_BUFFER_HARD_CAP = 8 * 1024 * 1024; /* RST when exceeded  */
static constexpr size_t TCP_TX_BUFFER_BACKPRESSURE = 256 * 1024;  /* pause host reads   */
static constexpr size_t TCP_TX_BUFFER_RESUME = 128 * 1024;	  /* resume host reads  */
static constexpr size_t TCP_RX_BUFFER_HARD_CAP = 8 * 1024 * 1024; /* RST when exceeded  */
static constexpr size_t TCP_RECV_BUF_SIZE = 65536;		  /* max TCP segment    */

/* TCP idle timeouts (seconds) */
static constexpr time_t TCP_TIMEOUT_ESTABLISHED = 3600; /* 1 hour - normal idle        */
static constexpr time_t TCP_TIMEOUT_CONNECTING = 10;	/* SYN / proxy handshake       */
static constexpr time_t TCP_TIMEOUT_FIN = 60;		/* FIN_WAIT_{1,2}, CLOSE_WAIT  */
static constexpr time_t TCP_TIMEOUT_CLOSING = 5;	/* TIME_WAIT, CLOSING          */

static void tcp_send_rst4(Context* ctx, const FlowKey4& key4, uint32_t seq, uint32_t ack) {
	TcpFlow dummy_flow = {};
	dummy_flow.key4 = key4;
	dummy_flow.is_ipv6 = false;
	dummy_flow.seq_to_guest = seq;
	dummy_flow.ack_to_guest = ack;
	tcp_send_packet4(ctx, &dummy_flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
}

static void tcp_send_rst6(Context* ctx, const FlowKey6& key6, uint32_t seq, uint32_t ack) {
	TcpFlow dummy_flow = {};
	dummy_flow.key6 = key6;
	dummy_flow.is_ipv6 = true;
	dummy_flow.seq_to_guest = seq;
	dummy_flow.ack_to_guest = ack;
	tcp_send_packet6(ctx, &dummy_flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
}

static size_t tcp_build_options(uint8_t flags, uint8_t* options) {
	size_t opt_len = 0;
	if (flags & TH_SYN) {
		tcp_opt_mss* mss_opt = reinterpret_cast<tcp_opt_mss*>(&options[opt_len]);
		*mss_opt = {
		    .kind = TCPOPT_MAXSEG,
		    .len = TCPOLEN_MAXSEG,
		    .mss = htons(65495),
		};
		opt_len += sizeof(tcp_opt_mss);

		options[opt_len++] = TCPOPT_NOP;

		tcp_opt_wscale* wscale_opt = reinterpret_cast<tcp_opt_wscale*>(&options[opt_len]);
		*wscale_opt = {
		    .kind = TCPOPT_WINDOW,
		    .len = TCPOLEN_WINDOW,
		    .shift = 8,
		};
		opt_len += sizeof(tcp_opt_wscale);
	}
	return opt_len;
}

void tcp_send_packet4(Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet4: data length too large (%zu)", len);
		return;
	}

	uint8_t options[40];
	size_t opt_len = tcp_build_options(flags, options);

	/* Single-threaded network loop: use static buffer for header only */
	static thread_local uint8_t frame_buf[sizeof(ip4_hdr) + sizeof(tcp_hdr) + 40];

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(frame_buf);
	tcp_hdr* r_tcp = reinterpret_cast<tcp_hdr*>(frame_buf + sizeof(ip4_hdr));
	uint8_t* r_opt = frame_buf + sizeof(ip4_hdr) + sizeof(tcp_hdr);

	/* IPv4 */
	ip4_set_ihl_version(r_ip, 4, sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(sizeof(ip4_hdr) + sizeof(tcp_hdr) + opt_len + len);
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = IPPROTO_TCP;
	r_ip->saddr = flow->key4.daddr4;
	r_ip->daddr = flow->key4.saddr4;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* TCP */
	r_tcp->source = flow->key4.dport;
	r_tcp->dest = flow->key4.sport;
	r_tcp->seq = htonl(flow->seq_to_guest);
	r_tcp->ack_seq = htonl(flow->ack_to_guest);
	tcp_set_doff(r_tcp, (sizeof(tcp_hdr) + opt_len) / 4);
	r_tcp->flags = flags;
	r_tcp->window = htons(65535); /* Large window */
	r_tcp->check = 0;
	r_tcp->urg_ptr = 0;

	if (opt_len > 0) {
		memcpy(r_opt, options, opt_len);
	}

	pseudo_hdr4 phdr = {.saddr = flow->key4.daddr4,
	    .daddr = flow->key4.saddr4,
	    .zero = 0,
	    .protocol = IPPROTO_TCP,
	    .len = htons(sizeof(tcp_hdr) + opt_len + len)};

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(r_tcp, sizeof(tcp_hdr) + opt_len, sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_tcp->check = finalize_checksum(sum);

	send_to_guest_v(ctx, frame_buf, sizeof(ip4_hdr) + sizeof(tcp_hdr) + opt_len, data, len);
}

void tcp_send_packet6(Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet6: data length too large (%zu)", len);
		return;
	}

	uint8_t options[40];
	size_t opt_len = tcp_build_options(flags, options);

	/* Single-threaded network loop: use static buffer to avoid 63KB stack allocation */
	static thread_local uint8_t frame_buf[sizeof(ip6_hdr) + sizeof(tcp_hdr) + 40];

	ip6_hdr* r_ip = reinterpret_cast<ip6_hdr*>(frame_buf);
	tcp_hdr* r_tcp = reinterpret_cast<tcp_hdr*>(frame_buf + sizeof(ip6_hdr));
	uint8_t* r_opt = frame_buf + sizeof(ip6_hdr) + sizeof(tcp_hdr);

	/* IPv6 */
	r_ip->vtf = htonl(0x60000000); /* Version 6 */
	r_ip->payload_len = htons(sizeof(tcp_hdr) + opt_len + len);
	r_ip->next_header = IPPROTO_TCP;
	r_ip->hop_limit = 64;
	memcpy(r_ip->saddr, flow->key6.daddr6, sizeof(r_ip->saddr));
	memcpy(r_ip->daddr, flow->key6.saddr6, sizeof(r_ip->daddr));

	/* TCP */
	r_tcp->source = flow->key6.dport;
	r_tcp->dest = flow->key6.sport;
	r_tcp->seq = htonl(flow->seq_to_guest);
	r_tcp->ack_seq = htonl(flow->ack_to_guest);
	tcp_set_doff(r_tcp, (sizeof(tcp_hdr) + opt_len) / 4);
	r_tcp->flags = flags;
	r_tcp->window = htons(65535); /* Large window */
	r_tcp->check = 0;
	r_tcp->urg_ptr = 0;

	if (opt_len > 0) {
		memcpy(r_opt, options, opt_len);
	}

	pseudo_hdr6 phdr = {
	    .saddr = {0},
	    .daddr = {0},
	    .len = htonl(sizeof(tcp_hdr) + opt_len + len),
	    .zeros = {0},
	    .next_header = IPPROTO_TCP,
	};
	memcpy(phdr.saddr, flow->key6.daddr6, sizeof(phdr.saddr));
	memcpy(phdr.daddr, flow->key6.saddr6, sizeof(phdr.daddr));

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(r_tcp, sizeof(tcp_hdr) + opt_len, sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_tcp->check = finalize_checksum(sum);

	send_to_guest_v(ctx, frame_buf, sizeof(ip6_hdr) + sizeof(tcp_hdr) + opt_len, data, len);
}

static inline void tcp_send_packet(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0) {
	if (flow->is_ipv6) {
		tcp_send_packet6(ctx, flow, flags, data, len);
	} else {
		tcp_send_packet4(ctx, flow, flags, data, len);
	}
}

static void tcp_rst_and_destroy(Context* ctx, TcpFlow* flow) {
	tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
	tcp_destroy_flow(ctx, flow);
}

void tcp_destroy_flow(Context* ctx, TcpFlow* flow) {
	if (flow->host_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		ctx->flows_by_fd.erase(flow->host_fd);
		/* close() is handled by ~TcpFlow via unique_ptr destruction below */
	}
	/* Erase from owning map last - unique_ptr runs ~TcpFlow() which closes host_fd */
	if (flow->is_ipv6) {
		ctx->ipv6_tcp_flows_by_key.erase(flow->key6);
	} else {
		ctx->ipv4_tcp_flows_by_key.erase(flow->key4);
	}
}

void push_to_guest(Context* ctx, TcpFlow* flow) {
	if (flow->state != TcpState::ESTABLISHED && flow->state != TcpState::CLOSE_WAIT) {
		return;
	}

	/* Max TCP payload per TUN frame: MTU minus IP and TCP headers */
	size_t max_seg =
	    NSTUN_MTU - (flow->is_ipv6 ? sizeof(ip6_hdr) : sizeof(ip4_hdr)) - sizeof(tcp_hdr);

	for (;;) {
		int32_t in_flight = flow->seq_to_guest - flow->ack_from_guest;
		int32_t available = flow->tx_buffer.size() - flow->tx_acked_offset;

		if (in_flight < 0) {
			/* Guest acked future data? Reset flight */
			flow->seq_to_guest = flow->ack_from_guest;
			in_flight = 0;
		}
		if (in_flight >= available) {
			if (flow->host_eof && available == 0) {
				if (!flow->fin_sent) {
					/* Stream fully flushed and host closed write-end */
					tcp_send_packet(
					    ctx, flow, NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_ACK);
					flow->seq_to_guest++;
					flow->fin_sent = true;
				}
			}
			return; /* Everything is in flight */
		}

		size_t to_send = available - in_flight;
		if (to_send > max_seg) to_send = max_seg;

		const uint8_t* data = flow->tx_buffer.data() + flow->tx_acked_offset + in_flight;
		uint8_t flags = NSTUN_TCP_FLAG_ACK;
		if (to_send >= (size_t)(available - in_flight)) {
			flags |= NSTUN_TCP_FLAG_PSH;
		}

		tcp_send_packet(ctx, flow, flags, data, to_send);
		flow->seq_to_guest += to_send;
	}
}

/* Returns true if the flow was destroyed (caller must not use flow afterward) */
bool flush_to_host(Context* ctx, TcpFlow* flow) {
	if (flow->rx_sent_offset >= flow->rx_buffer.size()) {
		return false;
	}

	size_t to_send = flow->rx_buffer.size() - flow->rx_sent_offset;
	ssize_t written = send(
	    flow->host_fd, flow->rx_buffer.data() + flow->rx_sent_offset, to_send, MSG_NOSIGNAL);

	if (written > 0) {
		flow->rx_sent_offset += written;
		if (flow->rx_sent_offset >= flow->rx_buffer.size()) {
			flow->rx_buffer.clear();
			flow->rx_sent_offset = 0;
		}

		/* We made progress, remove EPOLLOUT if empty */
		if (flow->rx_buffer.empty() && flow->epoll_out_registered) {
			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = flow->host_fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, flow->host_fd, &ev);
			flow->epoll_out_registered = false;
		}

		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
		return false;

	} else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		/* Apply backpressure, register EPOLLOUT */
		if (!flow->epoll_out_registered) {
			struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			    .data = {.fd = flow->host_fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, flow->host_fd, &ev);
			flow->epoll_out_registered = true;
		}
		return false;
	} else {
		/* Terminal error, RST the guest */
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
}

static void handle_socks5_init_host(Context* ctx, TcpFlow* flow, int fd) {
	socks5_auth_reply buf;
	ssize_t recv_len = recv(fd, &buf, sizeof(buf) - flow->proxy_rx_buffer.size(), MSG_DONTWAIT);
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) return;
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->proxy_rx_buffer.insert(flow->proxy_rx_buffer.end(), reinterpret_cast<uint8_t*>(&buf),
	    reinterpret_cast<uint8_t*>(&buf) + recv_len);
	if (flow->proxy_rx_buffer.size() < 2) return;

	if (!nstun::parse_socks5_auth_reply(std::span<const uint8_t>(
		flow->proxy_rx_buffer.data(), flow->proxy_rx_buffer.size()))) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->proxy_rx_buffer.clear();
	flow->state = TcpState::SOCKS5_CONNECTING;

	const uint8_t* addr = flow->is_ipv6 ? flow->key6.daddr6
					    : reinterpret_cast<const uint8_t*>(&flow->key4.daddr4);
	uint16_t port = flow->is_ipv6 ? flow->key6.dport : flow->key4.dport;

	if (nstun::send_socks5_connect(fd, addr, port, flow->is_ipv6) < 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
}

static bool handle_socks5_init_guest(Context* ctx, TcpFlow* flow, std::span<const uint8_t> data) {
	/* Guest data received during proxy negotiation - buffer it, don't forward yet. */
	flow->rx_buffer.insert(flow->rx_buffer.end(), data.begin(), data.end());
	return false;
}

static void handle_socks5_connecting_host(Context* ctx, TcpFlow* flow, int fd) {
	socks5_max_buf buf;
	while (true) {
		size_t current_len = flow->proxy_rx_buffer.size();
		size_t expected_len = 4; /* Minimum to find ATYP */

		if (current_len >= 4) {
			const auto* reply =
			    reinterpret_cast<const socks5_req*>(flow->proxy_rx_buffer.data());
			if (reply->atyp == SOCKS5_ATYP_IPV4) {
				expected_len = sizeof(socks5_req);
			} else if (reply->atyp == SOCKS5_ATYP_IPV6) {
				expected_len = sizeof(socks5_req6);
			} else if (reply->atyp == SOCKS5_ATYP_DOMAIN) {
				if (current_len >= 5) {
					const auto* dreq =
					    reinterpret_cast<const socks5_req_domain*>(
						flow->proxy_rx_buffer.data());
					expected_len = 5 + dreq->domain_len + 2;
				} else {
					expected_len = 5; /* Need 5th byte to know domain length */
				}
			} else {
				LOG_W("Unknown SOCKS5 ATYP: %u", reply->atyp);
				tcp_rst_and_destroy(ctx, flow);
				return;
			}
		}

		if (current_len >= expected_len) {
			break; /* We have enough data */
		}

		ssize_t recv_len = recv(fd, &buf, expected_len - current_len, MSG_DONTWAIT);
		if (recv_len == 0) {
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		flow->proxy_rx_buffer.insert(
		    flow->proxy_rx_buffer.end(), buf.data, buf.data + recv_len);
	}

	/* Validate SOCKS5 response */
	const auto* reply = reinterpret_cast<const socks5_req*>(flow->proxy_rx_buffer.data());
	if (reply->ver != SOCKS5_VERSION || reply->cmd != SOCKS5_REP_SUCCESS) {
		LOG_W("SOCKS5 connection failed: ver=%u rep=%u", reply->ver, reply->cmd);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	/* Full response received - release buffer and transition to ESTABLISHED */
	flow->proxy_rx_buffer.clear();
	flow->proxy_rx_buffer.shrink_to_fit();
	flow->state = TcpState::ESTABLISHED;
	tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
	flow->seq_to_guest++;
}

static void handle_http_connect_wait_host(Context* ctx, TcpFlow* flow, int fd) {
	uint8_t buf[HTTP_PROXY_RESPONSE_MAX];
	ssize_t recv_len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) return;
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	auto& rx = flow->proxy_rx_buffer;
	rx.insert(rx.end(), buf, buf + recv_len);

	size_t end_of_headers = nstun::find_end_of_headers(rx);
	if (end_of_headers == 0) {
		if (rx.size() > HTTP_PROXY_RESPONSE_MAX) {
			LOG_E("HTTP proxy response too long");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		return; /* Wait for more data */
	}

	if (!nstun::parse_http_connect_reply(rx)) {
		LOG_W("HTTP CONNECT failed: %.*s", (int)std::min(end_of_headers, (size_t)64),
		    rx.data());
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	/* Anything after the headers is tunnelled payload - forward it */
	if (rx.size() > end_of_headers) {
		flow->tx_buffer.insert(
		    flow->tx_buffer.end(), rx.data() + end_of_headers, rx.data() + rx.size());
	}
	/* Release proxy negotiation buffer - no longer needed */
	rx.clear();
	rx.shrink_to_fit();

	flow->state = TcpState::ESTABLISHED;
	tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
	flow->seq_to_guest++;

	if (!flow->tx_buffer.empty()) {
		push_to_guest(ctx, flow);
	}
}

static void handle_data_transfer_host(Context* ctx, TcpFlow* flow, int fd) {
	uint8_t buf[TCP_RECV_BUF_SIZE];
	ssize_t recv_len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (recv_len == 0) {
		handle_host_tcp_data_eof(ctx, flow, fd);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) return;
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->tx_buffer.insert(flow->tx_buffer.end(), buf, buf + recv_len);

	if (flow->tx_buffer.size() > TCP_TX_BUFFER_HARD_CAP) {
		LOG_W("TCP tx_buffer reached %zuMB hard cap, RST",
		    TCP_TX_BUFFER_HARD_CAP / (1024 * 1024));
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (flow->state != TcpState::SYN_SENT) {
		push_to_guest(ctx, flow);
	}

	if (flow->tx_buffer.size() - flow->tx_acked_offset > TCP_TX_BUFFER_BACKPRESSURE) {
		if (!flow->epoll_in_disabled) {
			struct epoll_event ev = {
			    .events = EPOLLERR | EPOLLHUP |
				      (flow->epoll_out_registered ? (uint32_t)EPOLLOUT : 0),
			    .data = {.fd = fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
			flow->epoll_in_disabled = true;
		}
	}
}

static bool handle_data_transfer_guest(Context* ctx, TcpFlow* flow, std::span<const uint8_t> data) {
	flow->rx_buffer.insert(flow->rx_buffer.end(), data.begin(), data.end());
	return flush_to_host(ctx, flow);
}

[[noreturn]] static void handle_unsupported_state_host(Context* ctx, TcpFlow* flow, int fd) {
	LOG_F("Unsupported TCP state %d in host event handler", (int)flow->state);
	abort();
}

[[noreturn]] static bool handle_unsupported_state_guest(
    Context* ctx, TcpFlow* flow, std::span<const uint8_t> data) {
	LOG_F("Unsupported TCP state %d in guest packet handler", (int)flow->state);
	abort();
}

static const TcpStateHandlers kStateTable[] = {
    [(int)TcpState::SYN_SENT] = {handle_data_transfer_host, handle_data_transfer_guest},
    [(int)TcpState::SOCKS5_INIT] = {handle_socks5_init_host, handle_socks5_init_guest},
    [(int)TcpState::SOCKS5_CONNECTING] = {handle_socks5_connecting_host, handle_socks5_init_guest},
    [(int)TcpState::HTTP_CONNECT_WAIT] = {handle_http_connect_wait_host, handle_socks5_init_guest},
    [(int)TcpState::ESTABLISHED] = {handle_data_transfer_host, handle_data_transfer_guest},
    [(int)TcpState::FIN_WAIT_1] = {handle_data_transfer_host, handle_data_transfer_guest},
    [(int)TcpState::FIN_WAIT_2] = {handle_data_transfer_host, handle_data_transfer_guest},
    [(int)TcpState::CLOSING] = {handle_unsupported_state_host, handle_unsupported_state_guest},
    [(int)TcpState::TIME_WAIT] = {handle_unsupported_state_host, handle_unsupported_state_guest},
    [(int)TcpState::CLOSE_WAIT] = {handle_data_transfer_host, handle_data_transfer_guest},
};

static void tcp_process_data(Context* ctx, TcpFlow* flow, const tcp_hdr* tcp,
    std::span<const uint8_t> payload, uint8_t doff) {
	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	if (flow->inbound && flow->state == TcpState::SYN_SENT &&
	    (tcp->flags & NSTUN_TCP_FLAG_SYN) && (tcp->flags & NSTUN_TCP_FLAG_ACK)) {
		flow->state = TcpState::ESTABLISHED;
		flow->ack_from_guest = ack;
		flow->seq_from_guest = seq + 1;
		flow->ack_to_guest = flow->seq_from_guest;
		flow->syn_acked = true;

		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);

		if (!flow->tx_buffer.empty()) {
			push_to_guest(ctx, flow);
		}

		if (flow->epoll_in_disabled) {
			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLERR | EPOLLHUP |
				      (flow->epoll_out_registered ? (uint32_t)EPOLLOUT : 0),
			    .data = {.fd = flow->host_fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, flow->host_fd, &ev);
			flow->epoll_in_disabled = false;
		}
		return;
	}

	if (tcp->flags & NSTUN_TCP_FLAG_RST) {
		LOG_D("Received RST from guest");
		tcp_destroy_flow(ctx, flow);
		return;
	}

	if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::FIN_WAIT_1 ||
	    flow->state == TcpState::FIN_WAIT_2 || flow->state == TcpState::SYN_SENT ||
	    flow->state == TcpState::CLOSE_WAIT) {
		const uint8_t* data = payload.data() + doff;
		size_t data_len = payload.size() - doff;

		/* Defense-in-depth: cap to MTU to prevent int32_t overflow in seq arithmetic */
		if (data_len > NSTUN_MTU) {
			return;
		}

		if (data_len > 0) {
			int32_t diff = seq - flow->ack_to_guest;
			int32_t end_diff = (seq + (uint32_t)data_len) - flow->ack_to_guest;

			if (diff <= 0 && end_diff > 0) {
				uint32_t overlap = flow->ack_to_guest - seq;
				const uint8_t* new_data = data + overlap;
				size_t new_data_len = data_len - overlap;

				if (flow->rx_buffer.size() + new_data_len >
				    TCP_RX_BUFFER_HARD_CAP) {
					LOG_D("TCP rx_buffer reached 8MB limit (DoS protection), "
					      "dropping");
					return;
				}

				flow->seq_from_guest += new_data_len;
				flow->ack_to_guest = flow->seq_from_guest;

				size_t state_idx = static_cast<size_t>(flow->state);
				if (state_idx < sizeof(kStateTable) / sizeof(kStateTable[0])) {
					if (kStateTable[state_idx].on_guest_packet(ctx, flow,
						std::span<const uint8_t>(new_data, new_data_len))) {
						return; /* Flow was destroyed */
					}
				}
			} else if (diff > 0) {
				tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
			} else {
				tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
			}
		}

		/* Process ACKs from guest */
		if (tcp->flags & NSTUN_TCP_FLAG_ACK) {
			if (flow->state == TcpState::SYN_SENT) {
				flow->state = TcpState::ESTABLISHED;
				flow->ack_from_guest = ack;
				flow->syn_acked = true;
			} else {
				int32_t acked_bytes = ack - flow->ack_from_guest;
				if (acked_bytes > 0) {
					flow->ack_from_guest = ack;
					if (!flow->syn_acked) {
						flow->syn_acked = true;
						acked_bytes--;
					}
					if (flow->fin_sent && !flow->fin_acked &&
					    ack == flow->seq_to_guest) {
						flow->fin_acked = true;
						acked_bytes--;
					}
					/* acked_bytes is now reliably >= 0 after the
					 * SYN/FIN decrements above */
					size_t advance =
					    (acked_bytes > 0) ? (size_t)acked_bytes : 0;
					flow->tx_acked_offset += advance;

					size_t erase_len = flow->tx_acked_offset;
					if (erase_len > flow->tx_buffer.size()) {
						erase_len = flow->tx_buffer.size();
					}

					if (erase_len > 65536 ||
					    erase_len == flow->tx_buffer.size()) {
						flow->tx_buffer.erase(flow->tx_buffer.begin(),
						    flow->tx_buffer.begin() + erase_len);
						flow->tx_acked_offset -= erase_len;
					}

					if (flow->epoll_in_disabled && !flow->host_eof &&
					    (flow->tx_buffer.size() - flow->tx_acked_offset <
						TCP_TX_BUFFER_RESUME)) {
						struct epoll_event ev = {
						    .events = EPOLLIN | EPOLLERR | EPOLLHUP |
							      (flow->epoll_out_registered
								      ? (uint32_t)EPOLLOUT
								      : 0),
						    .data = {.fd = flow->host_fd}};
						epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD,
						    flow->host_fd, &ev);
						flow->epoll_in_disabled = false;
					}

					push_to_guest(ctx, flow);
				} else if (acked_bytes == 0 && data_len == 0 &&
					   !(tcp->flags & (NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_SYN |
							      NSTUN_TCP_FLAG_RST))) {
					/* Duplicate ACK -> Fast Retransmit */
					flow->seq_to_guest = flow->ack_from_guest;
					push_to_guest(ctx, flow);
				}
			}

			if (flow->state == TcpState::FIN_WAIT_1 && ack == flow->seq_to_guest) {
				flow->state = TcpState::FIN_WAIT_2;
			}
		} else if (data_len == 0 &&
			   !(tcp->flags &
			       (NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_RST))) {
			flow->seq_to_guest = flow->ack_from_guest;
			push_to_guest(ctx, flow);
		}

		if (tcp->flags & NSTUN_TCP_FLAG_FIN) {
			LOG_D("Received FIN from guest");
			flow->seq_from_guest++;
			flow->ack_to_guest = flow->seq_from_guest;

			tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);

			shutdown(flow->host_fd, SHUT_WR);
			flow->guest_eof = true;

			if (flow->state == TcpState::ESTABLISHED) {
				flow->state = TcpState::CLOSE_WAIT;
			} else if (flow->state == TcpState::FIN_WAIT_1) {
				flow->state = TcpState::CLOSING;
			} else if (flow->state == TcpState::FIN_WAIT_2) {
				flow->state = TcpState::TIME_WAIT;
			}

			push_to_guest(ctx, flow);
			return;
		}
	}
}

/*
 * Initialize all common TcpFlow fields for a new outbound connection.
 * Callers set key4/key6 themselves (type-specific) before calling this.
 *
 * seq_from_guest: the SYN sequence number from the guest + 1.
 */
static void init_outbound_flow_common(
    TcpFlow* flow, int fd, bool is_ipv6, ProxyMode proxy, uint32_t seq_from_guest) {
	flow->host_fd = fd;
	flow->is_ipv6 = is_ipv6;
	flow->state = TcpState::SYN_SENT;
	flow->proxy_mode = proxy;
	flow->host_eof = false;
	flow->guest_eof = false;
	flow->fin_sent = false;
	flow->syn_acked = false;
	flow->fin_acked = false;
	flow->seq_to_guest = (uint32_t)util::rnd64();
	flow->seq_from_guest = seq_from_guest;
	flow->ack_to_guest = seq_from_guest;
	flow->ack_from_guest = flow->seq_to_guest; /* ACK our own SYN */
	flow->tx_acked_offset = 0;
	flow->rx_sent_offset = 0;
	flow->epoll_out_registered = true;
	flow->epoll_in_disabled = false;
	flow->inbound = false;
	flow->last_active = time(NULL);
}

/*
 * Attempt a non-blocking connect() and dispatch the result.
 *
 * - Immediate success (loopback / same-host): calls handle_host_tcp_connected.
 * - EINPROGRESS: returns; EPOLLOUT will fire when the connection completes.
 * - Any other error: RSTs the guest and destroys the flow.
 */
static void tcp_do_connect(
    Context* ctx, TcpFlow* flow, int fd, const struct sockaddr* addr, socklen_t addrlen) {
	int ret = connect(fd, addr, addrlen);
	if (ret == 0) {
		handle_host_tcp_connected(ctx, flow, fd);
	} else if (errno == EINPROGRESS) {
		/* Normal non-blocking result - EPOLLOUT will fire on completion */
	} else {
		PLOG_E("connect() failed");
		tcp_destroy_flow(ctx, flow);
	}
}

void handle_tcp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(tcp_hdr)) {
		return;
	}

	const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(payload.data());
	uint8_t doff = tcp_doff(tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > payload.size()) {
		return;
	}

	/* Validate TCP checksum */
	pseudo_hdr4 phdr = {.saddr = ip->saddr,
	    .daddr = ip->daddr,
	    .zero = 0,
	    .protocol = IPPROTO_TCP,
	    .len = htons(payload.size())};
	uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	csum = compute_checksum_part(payload.data(), payload.size(), csum);
	if (finalize_checksum(csum) != 0) {
		LOG_D("Invalid IPv4 TCP checksum, dropping");
		return;
	}

	FlowKey4 key4 = {ip->saddr, ip->daddr, tcp->source, tcp->dest};

	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	auto it = ctx->ipv4_tcp_flows_by_key.find(key4);
	TcpFlow* flow = nullptr;

	if (it != ctx->ipv4_tcp_flows_by_key.end()) {
		flow = it->second.get();
		flow->last_active = time(NULL);
	} else {
		if (ctx->ipv4_tcp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W(
			    "Maximum number of TCP flows (%zu) reached, dropping", NSTUN_MAX_FLOWS);
			return;
		}

		if (!(tcp->flags & NSTUN_TCP_FLAG_SYN)) {
			return;
		}

		/* SYN: evaluate policies */
		uint16_t guest_port = ntohs(tcp->source);
		uint16_t dest_port = ntohs(tcp->dest);

		RuleResult rule = evaluate_rules4(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP,
		    ip->saddr, ip->daddr, guest_port, dest_port);

		if (rule.action == NSTUN_ACTION_DROP) {
			LOG_D("TCP connect to %s:%u dropped by policy",
			    ip4_to_string(ip->daddr).c_str(), dest_port);
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			LOG_D("TCP connect to %s:%u rejected by policy",
			    ip4_to_string(ip->daddr).c_str(), dest_port);
			tcp_send_rst4(ctx, key4, 0, seq + 1);
			return;
		}

		/* All checks passed: open a socket and connect to the destination. */
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket(AF_INET, SOCK_STREAM)");
			return;
		}

		int opt = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

		struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
		if (rule.redirect_ip4 && rule.redirect_port) {
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			LOG_D("Redirecting TCP flow guest %u to host %s:%u via policy (fd=%d)",
			    guest_port, ip4_to_string(rule.redirect_ip4).c_str(),
			    rule.redirect_port, fd);
		} else {
			dest_addr.sin_addr.s_addr = key4.daddr4;
			dest_addr.sin_port = tcp->dest;
			LOG_D("New TCP flow guest %u -> host %s:%u (fd=%d)", guest_port,
			    ip4_to_string(key4.daddr4).c_str(), dest_port, fd);
		}

		struct epoll_event ev = {
		    .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			PLOG_E("epoll_ctl(EPOLL_CTL_ADD)");
			close(fd);
			return;
		}

		std::unique_ptr<TcpFlow> flow_ptr = std::make_unique<TcpFlow>();
		flow = flow_ptr.get();
		flow->key4 = key4;
		init_outbound_flow_common(
		    flow, fd, /*is_ipv6=*/false, proxy_mode_from_action(rule.action), seq + 1);

		ctx->ipv4_tcp_flows_by_key[key4] = std::move(flow_ptr);
		ctx->flows_by_fd[fd] = flow;

		tcp_do_connect(ctx, flow, fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		return;
	}

	tcp_process_data(ctx, flow, tcp, payload, doff);
}

void handle_host_tcp_connected(Context* ctx, TcpFlow* flow, int fd) {
	int err = 0;
	socklen_t errlen = sizeof(err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
	if (err != 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	struct epoll_event ev = {.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
	flow->epoll_out_registered = false;

	switch (flow->proxy_mode) {
	case ProxyMode::NONE:
		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;
		return;

	case ProxyMode::HTTP_CONNECT: {
		flow->state = TcpState::HTTP_CONNECT_WAIT;
		const uint8_t* addr = flow->is_ipv6
					  ? flow->key6.daddr6
					  : reinterpret_cast<const uint8_t*>(&flow->key4.daddr4);
		uint16_t port = flow->is_ipv6 ? flow->key6.dport : flow->key4.dport;
		if (nstun::send_http_connect(fd, addr, port, flow->is_ipv6) < 0) {
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}

	case ProxyMode::SOCKS5:
		flow->state = TcpState::SOCKS5_INIT;
		if (nstun::send_socks5_greeting(fd) < 0) {
			PLOG_E("send() SOCKS5 greeting");
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}
}

void handle_host_tcp_data(Context* ctx, TcpFlow* flow, int fd) {
	size_t state_idx = static_cast<size_t>(flow->state);
	if (state_idx >= sizeof(kStateTable) / sizeof(kStateTable[0])) {
		LOG_W("Invalid TCP state: %zu", state_idx);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	kStateTable[state_idx].on_host_data(ctx, flow, fd);
}

/* Out-of-switch dispatch for goto targets above */
void handle_host_tcp_data_eof(Context* ctx, TcpFlow* flow, int fd) {
	LOG_D("Handling EOF. host_eof=%d epoll_in_disabled=%d", flow->host_eof,
	    flow->epoll_in_disabled);
	if (!flow->host_eof) {
		flow->host_eof = true;
		if (!flow->epoll_in_disabled) {
			struct epoll_event ev = {
			    .events = EPOLLERR | EPOLLHUP |
				      (flow->epoll_out_registered ? (uint32_t)EPOLLOUT : 0),
			    .data = {.fd = fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
				PLOG_E("epoll_ctl(EPOLL_CTL_MOD) failed in eof");
			} else {
				LOG_D("epoll_ctl(EPOLL_CTL_MOD) removed EPOLLIN successfully");
			}
			flow->epoll_in_disabled = true;
		}
	}
	push_to_guest(ctx, flow);
}

void handle_host_tcp(Context* ctx, TcpFlow* flow, uint32_t events) {
	int fd = flow->host_fd;
	flow->last_active = time(NULL);

	LOG_D("handle_host_tcp fd=%d, events=0x%x, state=%d", fd, events, (int)flow->state);

	if (flow->state == TcpState::SYN_SENT && (events & EPOLLOUT)) {
		if (flow->inbound) {
			/* Inbound flow already connected, waiting for SYN-ACK from guest */
			/* Avoid immediate EPOLLOUT spin, wait for data */
			if (flow->epoll_out_registered) {
				struct epoll_event ev_mod = {
				    .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
				epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev_mod);
				flow->epoll_out_registered = false;
			}
		} else {
			handle_host_tcp_connected(ctx, flow, fd);
			return;
		}
	}

	if (events & EPOLLIN) {
		handle_host_tcp_data(ctx, flow, fd);
		/* handle_host_tcp_data may destroy the flow (e.g. RST, error) */
		if (ctx->flows_by_fd.find(fd) == ctx->flows_by_fd.end()) {
			return;
		}
	}

	if ((events & EPOLLOUT) && flow->rx_buffer.size() > flow->rx_sent_offset) {
		if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::CLOSE_WAIT) {
			if (flush_to_host(ctx, flow)) {
				return; /* Flow was destroyed */
			}
		}
	}

	/* Handle EPOLLHUP/EPOLLERR: the host socket is dead.
	 * If we didn't already process this via EPOLLIN above, clean up now
	 * to avoid spinning forever on a hung-up fd */
	if (events & (EPOLLHUP | EPOLLERR)) {
		if (flow->host_eof && flow->guest_eof) {
			/* Both sides are done, destroy the flow */
			tcp_destroy_flow(ctx, flow);
			return;
		}
		if (!flow->host_eof) {
			/* Treat HUP as EOF from host */
			flow->host_eof = true;
			flow->epoll_in_disabled = true;
			push_to_guest(ctx, flow);
			if (ctx->flows_by_fd.find(fd) == ctx->flows_by_fd.end()) {
				return;
			}
		}
		if (flow->guest_eof) {
			tcp_destroy_flow(ctx, flow);
			return;
		}
	}
}

void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_tcp_accept listen_fd=%d", listen_fd);
	size_t tcp_flow_count =
	    ctx->ipv4_tcp_flows_by_key.size() + ctx->ipv6_tcp_flows_by_key.size();
	if (tcp_flow_count >= NSTUN_MAX_FLOWS) {
		LOG_W("Max TCP flows (%zu) reached, dropping inbound connection", tcp_flow_count);
		return;
	}

	struct sockaddr_storage client_ss = {};
	socklen_t addrlen = sizeof(client_ss);
	int fd = accept4(
	    listen_fd, (struct sockaddr*)&client_ss, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_E("accept4()");
		}
		return;
	}

	LOG_D("Accepted fd=%d", fd);

	int opt = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	TcpFlow* flow;
	std::unique_ptr<TcpFlow> flow_ptr(new TcpFlow());
	bool flow_success = false;
	defer {
		if (!flow_success) tcp_destroy_flow(ctx, flow);
	};

	flow = flow_ptr.get();
	flow->host_fd = fd;
	flow->is_ipv6 = rule.is_ipv6;

	struct epoll_event ev = {.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for host accept");
		return;
	}

	flow->state = TcpState::SYN_SENT;
	flow->epoll_out_registered = false;
	flow->epoll_in_disabled = false;
	flow->host_eof = false;
	flow->guest_eof = false;
	flow->fin_sent = false;
	flow->syn_acked = false;
	flow->fin_acked = false;
	flow->proxy_mode = ProxyMode::NONE; /* Proxies not supported for inbound */
	flow->last_active = time(NULL);
	flow->inbound = true;

	flow->seq_from_guest = 0;
	flow->ack_to_guest = 0;
	flow->seq_to_guest = (uint32_t)util::rnd64();
	flow->ack_from_guest = flow->seq_to_guest;
	flow->tx_acked_offset = 0;

	if (rule.is_ipv6) {
		struct sockaddr_in6* client6 = reinterpret_cast<struct sockaddr_in6*>(&client_ss);
		struct sockaddr_in6 server6 = INIT_SOCKADDR_IN6(AF_INET6);
		socklen_t servlen6 = sizeof(server6);
		getsockname(fd, (struct sockaddr*)&server6, &servlen6);

		/* Loopback→gateway rewrite for IPv6: prevent martian drops in guest */
		uint8_t client_ip6[IPV6_ADDR_LEN];
		memcpy(client_ip6, &client6->sin6_addr, sizeof(client_ip6));
		if (IN6_IS_ADDR_LOOPBACK(&client6->sin6_addr)) {
			memcpy(client_ip6, ctx->host_ip6, sizeof(client_ip6));
		}

		FlowKey6 key6 = {};
		memcpy(key6.saddr6, rule.redirect_ip6, sizeof(key6.saddr6));
		bool has_redirect_ip6 =
		    !IN6_IS_ADDR_UNSPECIFIED((const struct in6_addr*)rule.redirect_ip6);
		if (!has_redirect_ip6) {
			memcpy(key6.saddr6, ctx->guest_ip6, sizeof(key6.saddr6));
		}
		memcpy(key6.daddr6, client_ip6, sizeof(key6.daddr6));
		key6.sport = rule.redirect_port ? htons(rule.redirect_port) : server6.sin6_port;
		key6.dport = client6->sin6_port;

		if (ctx->ipv6_tcp_flows_by_key.find(key6) != ctx->ipv6_tcp_flows_by_key.end()) {
			LOG_W("IPv6 flow already exists");
			return;
		}

		flow->key6 = key6;
		ctx->ipv6_tcp_flows_by_key[key6] = std::move(flow_ptr);
		ctx->flows_by_fd[fd] = flow;

		LOG_D("Sending SYN to guest (IPv6)");
		tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_SYN);
		flow->seq_to_guest++;

		LOG_D("Accepted inbound TCP6 %s:%u -> %s:%u (fd=%d)",
		    ip6_to_string(key6.daddr6).c_str(), ntohs(key6.dport),
		    ip6_to_string(key6.saddr6).c_str(), ntohs(key6.sport), fd);
		flow_success = true;
	} else {
		struct sockaddr_in* client4 = reinterpret_cast<struct sockaddr_in*>(&client_ss);
		struct sockaddr_in server4 = INIT_SOCKADDR_IN(AF_INET);
		socklen_t servlen4 = sizeof(server4);
		getsockname(fd, (struct sockaddr*)&server4, &servlen4);

		uint32_t client_ip = client4->sin_addr.s_addr;
		if (client_ip == htonl(INADDR_LOOPBACK)) {
			client_ip = ctx->host_ip4; /* Prevent martian drops in guest */
		}

		FlowKey4 key4 = {
		    .saddr4 = rule.redirect_ip4 ? rule.redirect_ip4 : ctx->guest_ip4,
		    .daddr4 = client_ip,
		    .sport = rule.redirect_port ? htons(rule.redirect_port) : server4.sin_port,
		    .dport = client4->sin_port,
		};

		if (ctx->ipv4_tcp_flows_by_key.find(key4) != ctx->ipv4_tcp_flows_by_key.end()) {
			LOG_W("Flow already exists");
			return;
		}

		flow->key4 = key4;
		ctx->ipv4_tcp_flows_by_key[key4] = std::move(flow_ptr);
		ctx->flows_by_fd[fd] = flow;

		/* Initiate the flow to the guest by sending SYN */
		LOG_D("Sending SYN to guest");
		tcp_send_packet4(ctx, flow, NSTUN_TCP_FLAG_SYN);
		flow->seq_to_guest++;

		LOG_D("Accepted inbound TCP %s:%u -> %s:%u (fd=%d)",
		    ip4_to_string(key4.daddr4).c_str(), ntohs(key4.dport),
		    ip4_to_string(key4.saddr4).c_str(), ntohs(key4.sport), fd);
		flow_success = true;
	}
}

void handle_tcp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(tcp_hdr)) return;
	const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(payload.data());
	uint8_t doff = tcp_doff(tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > payload.size()) return;

	/* Validate TCP checksum */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(payload.size());
	phdr.next_header = IPPROTO_TCP;
	memcpy(phdr.saddr, ip->saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, ip->daddr, sizeof(phdr.daddr));
	uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	csum = compute_checksum_part(payload.data(), payload.size(), csum);
	if (finalize_checksum(csum) != 0) {
		LOG_D("Invalid IPv6 TCP checksum, dropping");
		return;
	}

	FlowKey6 key6 = {};
	memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
	memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
	key6.sport = tcp->source;
	key6.dport = tcp->dest;

	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	auto it = ctx->ipv6_tcp_flows_by_key.find(key6);
	TcpFlow* flow = nullptr;

	if (it != ctx->ipv6_tcp_flows_by_key.end()) {
		flow = it->second.get();
		flow->last_active = time(NULL);
	} else {
		if (ctx->ipv6_tcp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of IPv6 TCP flows (%zu) reached, dropping",
			    NSTUN_MAX_FLOWS);
			return;
		}

		if (!(tcp->flags & NSTUN_TCP_FLAG_SYN)) return;

		uint16_t guest_port = ntohs(tcp->source);
		uint16_t dest_port = ntohs(tcp->dest);

		RuleResult rule = evaluate_rules6(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP,
		    ip->saddr, ip->daddr, guest_port, dest_port);

		if (rule.action == NSTUN_ACTION_DROP) {
			LOG_D("IPv6 TCP connect to port %u dropped by policy", dest_port);
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			LOG_D("IPv6 TCP connect to port %u rejected by policy", dest_port);
			tcp_send_rst6(ctx, key6, 0, seq + 1);
			return;
		}

		bool use_proxy = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5 ||
				  rule.action == NSTUN_ACTION_ENCAP_CONNECT);

		/* Proxy connections always go via an IPv4 socket to the proxy host */
		int family = use_proxy ? AF_INET : AF_INET6;
		int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket() IPv6 TCP outbound");
			return;
		}

		int opt = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

		struct epoll_event ev = {
		    .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for IPv6 TCP");
			close(fd);
			return;
		}

		std::unique_ptr<TcpFlow> flow_ptr = std::make_unique<TcpFlow>();
		flow = flow_ptr.get();
		flow->key6 = key6;
		init_outbound_flow_common(
		    flow, fd, /*is_ipv6=*/true, proxy_mode_from_action(rule.action), seq + 1);

		ctx->ipv6_tcp_flows_by_key[key6] = std::move(flow_ptr);
		ctx->flows_by_fd[fd] = flow;

		if (use_proxy) {
			/* Proxy is always IPv4 */
			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			LOG_D("Connecting IPv6 TCP flow guest %u to IPv4 proxy port %u (fd=%d)",
			    guest_port, rule.redirect_port, fd);
			tcp_do_connect(
			    ctx, flow, fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		} else {
			/* Direct IPv6 connection (or IPv6 redirect) */
			struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);
			if (rule.has_redirect_ip6 && rule.redirect_port) {
				memcpy(&dest_addr.sin6_addr, rule.redirect_ip6,
				    sizeof(dest_addr.sin6_addr));
				dest_addr.sin6_port = htons(rule.redirect_port);
				LOG_D("Redirecting IPv6 TCP flow guest %u to %s:%u via policy "
				      "(fd=%d)",
				    guest_port, ip6_to_string(rule.redirect_ip6).c_str(),
				    rule.redirect_port, fd);
			} else {
				memcpy(
				    &dest_addr.sin6_addr, key6.daddr6, sizeof(dest_addr.sin6_addr));
				dest_addr.sin6_port = tcp->dest;
				LOG_D("New IPv6 TCP flow guest %u -> host %s:%u (fd=%d)",
				    guest_port, ip6_to_string(key6.daddr6).c_str(), dest_port, fd);
			}
			tcp_do_connect(
			    ctx, flow, fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		}
		return;
	}

	return tcp_process_data(ctx, flow, tcp, payload, doff);
}

void TcpFlow::handle_host_event(Context* ctx, int fd, uint32_t events) {
	if (fd == this->host_fd) {
		handle_host_tcp(ctx, this, events);
	}
}

void TcpFlow::periodic_check(Context* ctx, time_t now) {
	if (this->seq_to_guest > this->ack_from_guest && (now - this->last_active >= 2)) {
		LOG_D("TCP RTO triggered for flow (fd=%d)", this->host_fd);
		this->seq_to_guest = this->ack_from_guest;
		push_to_guest(ctx, this);
		this->last_active = now;
	}
}

bool TcpFlow::is_stale(time_t now) const {
	time_t timeout = TCP_TIMEOUT_ESTABLISHED;
	if (this->state == TcpState::SYN_SENT || this->state == TcpState::SOCKS5_INIT ||
	    this->state == TcpState::SOCKS5_CONNECTING ||
	    this->state == TcpState::HTTP_CONNECT_WAIT) {
		timeout = TCP_TIMEOUT_CONNECTING;
	} else if (this->state == TcpState::TIME_WAIT || this->state == TcpState::CLOSING) {
		timeout = TCP_TIMEOUT_CLOSING;
	} else if (this->state == TcpState::CLOSE_WAIT) {
		timeout = TCP_TIMEOUT_FIN;
	} else if (this->state == TcpState::FIN_WAIT_1 || this->state == TcpState::FIN_WAIT_2) {
		timeout = TCP_TIMEOUT_FIN;
	}

	return (now - this->last_active) > timeout;
}

void TcpFlow::destroy(Context* ctx) {
	if (is_ipv6) {
		LOG_D(
		    "GC: stale TCP flow (IPv6, sport=%u, state=%d)", ntohs(key6.sport), (int)state);
	} else {
		LOG_D("GC: stale TCP flow (sport=%u, state=%d)", ntohs(key4.sport), (int)state);
	}
	tcp_destroy_flow(ctx, this);
}

} /* namespace nstun */
