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
#include <sys/syscall.h>
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
typedef bool (*GuestPacketHandler)(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len);

/* --- buffer helpers ------------------------------------ */

static bool buffer_append(
    uint8_t* buf, size_t* len, size_t max_len, const uint8_t* data, size_t data_len) {
	if (*len > max_len || data_len > max_len - *len) {
		return false;
	}
	memcpy(buf + *len, data, data_len);
	*len += data_len;
	return true;
}

static void buffer_consume(uint8_t* buf, size_t* len, size_t consume_len) {
	if (consume_len == 0) {
		return;
	}
	if (consume_len > *len) {
		consume_len = *len;
	}
	memmove(buf, buf + consume_len, *len - consume_len);
	*len -= consume_len;
}

static uint32_t generate_isn() {
	uint32_t isn;
	if (util::syscall(__NR_getrandom, (uintptr_t)&isn, sizeof(isn), 0) != sizeof(isn)) {
		isn = static_cast<uint32_t>(util::rnd64());
	}
	return isn;
}

static inline bool append_proxy_rx(TcpFlow* flow, const uint8_t* data, size_t len) {
	return buffer_append(
	    flow->c_proxy_rx_buf.get(), &flow->c_proxy_rx_len, PROXY_RX_BUF_CAP, data, len);
}

static inline bool append_tcp_rx(TcpFlow* flow, const uint8_t* data, size_t len) {
	return buffer_append(
	    flow->c_tcp_rx_buf.get(), &flow->c_tcp_rx_len, TCP_RX_BUF_CAP, data, len);
}

static inline bool append_tcp_tx(TcpFlow* flow, const uint8_t* data, size_t len) {
	return buffer_append(
	    flow->c_tcp_tx_buf.get(), &flow->c_tcp_tx_len, TCP_TX_BUF_CAP, data, len);
}

static bool tcp_update_host_mask(TcpFlow* flow) {
	uint32_t events = EPOLLERR | EPOLLHUP;
	if (!flow->epoll_in_disabled) {
		events |= EPOLLIN;
	}
	if (flow->epoll_out_registered) {
		events |= EPOLLOUT;
	}
	return monitor::modFd(flow->header.host_fd, events);
}

/* --- state machine table ------------------------------- */

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

/* TCP buffer high-water marks */

static constexpr size_t TCP_RECV_BUF_SIZE = 65536; /* max TCP segment    */

/* TCP idle timeouts (seconds) */
static constexpr time_t TCP_TIMEOUT_ESTABLISHED = 300; /* 5 minutes - normal idle */
static constexpr time_t TCP_TIMEOUT_CONNECTING = 10;   /* SYN / proxy handshake */
static constexpr time_t TCP_TIMEOUT_FIN = 60;	       /* FIN_WAIT_{1,2}, CLOSE_WAIT */
static constexpr time_t TCP_TIMEOUT_CLOSING = 5;       /* TIME_WAIT, CLOSING */
static constexpr time_t TCP_TIMEOUT_RTO = 2;	       /* Retransmission timeout */

static constexpr size_t kMaxTcpOptions = 40;

/* --- packet crafting ----------------------------------- */

static void tcp_send_rst4(Context* ctx, const FlowKey4& key4, uint32_t seq, uint32_t ack) {
	struct {
		ip4_hdr ip;
		tcp_hdr tcp;
	} frame = {};

	/* IPv4 */
	ip4_set_ihl_version(&frame.ip, 4, sizeof(ip4_hdr) / 4);
	frame.ip.tos = 0;
	frame.ip.tot_len = htons(sizeof(ip4_hdr) + sizeof(tcp_hdr));
	frame.ip.id = 0;
	frame.ip.frag_off = 0;
	frame.ip.ttl = 64;
	frame.ip.protocol = IPPROTO_TCP;
	frame.ip.saddr = key4.daddr4;
	frame.ip.daddr = key4.saddr4;
	frame.ip.check = 0;
	frame.ip.check = compute_checksum(&frame.ip, sizeof(ip4_hdr));

	/* TCP */
	frame.tcp.source = key4.dport;
	frame.tcp.dest = key4.sport;
	frame.tcp.seq = htonl(seq);
	frame.tcp.ack_seq = htonl(ack);
	tcp_set_doff(&frame.tcp, sizeof(tcp_hdr) / 4);
	frame.tcp.flags = NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK;
	frame.tcp.window = 0;
	frame.tcp.check = 0;
	frame.tcp.urg_ptr = 0;

	pseudo_hdr4 phdr = {.saddr = key4.daddr4,
	    .daddr = key4.saddr4,
	    .zero = 0,
	    .protocol = IPPROTO_TCP,
	    .len = htons(sizeof(tcp_hdr))};

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(&frame.tcp, sizeof(tcp_hdr), sum);
	frame.tcp.check = finalize_checksum(sum);

	if (!send_to_guest_v(ctx, &frame, sizeof(frame), nullptr, 0)) {
		LOG_W("tcp_send_rst4: failed to send RST to guest");
	}
}

static void tcp_send_rst6(Context* ctx, const FlowKey6& key6, uint32_t seq, uint32_t ack) {
	struct {
		ip6_hdr ip;
		tcp_hdr tcp;
	} frame = {};

	/* IPv6 */
	frame.ip.vtf = htonl(0x60000000);
	frame.ip.payload_len = htons(sizeof(tcp_hdr));
	frame.ip.next_header = IPPROTO_TCP;
	frame.ip.hop_limit = 64;
	memcpy(frame.ip.saddr, key6.daddr6, sizeof(frame.ip.saddr));
	memcpy(frame.ip.daddr, key6.saddr6, sizeof(frame.ip.daddr));

	/* TCP */
	frame.tcp.source = key6.dport;
	frame.tcp.dest = key6.sport;
	frame.tcp.seq = htonl(seq);
	frame.tcp.ack_seq = htonl(ack);
	tcp_set_doff(&frame.tcp, sizeof(tcp_hdr) / 4);
	frame.tcp.flags = NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK;
	frame.tcp.window = 0;
	frame.tcp.check = 0;
	frame.tcp.urg_ptr = 0;

	pseudo_hdr6 phdr = {
	    .saddr = {0},
	    .daddr = {0},
	    .len = htonl(sizeof(tcp_hdr)),
	    .zeros = {0},
	    .next_header = IPPROTO_TCP,
	};
	memcpy(phdr.saddr, key6.daddr6, sizeof(phdr.saddr));
	memcpy(phdr.daddr, key6.saddr6, sizeof(phdr.daddr));

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(&frame.tcp, sizeof(tcp_hdr), sum);
	frame.tcp.check = finalize_checksum(sum);

	if (!send_to_guest_v(ctx, &frame, sizeof(frame), nullptr, 0)) {
		LOG_W("tcp_send_rst6: failed to send RST to guest");
	}
}

static size_t tcp_build_options(uint8_t flags, uint8_t* options, size_t max_len) {
	size_t opt_len = 0;
	if (flags & TH_SYN) {
		tcp_opt_mss mss_opt = {
		    .kind = TCPOPT_MAXSEG,
		    .len = TCPOLEN_MAXSEG,
		    .mss = htons(65495),
		};
		if (opt_len + sizeof(mss_opt) > max_len) {
			return opt_len;
		}
		memcpy(&options[opt_len], &mss_opt, sizeof(mss_opt));
		opt_len += sizeof(mss_opt);
	}
	return opt_len;
}

bool tcp_send_packet4(
    Context* ctx, const TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet4: data length too large (%zu)", len);
		return false;
	}

	uint8_t options[kMaxTcpOptions] = {};
	size_t opt_len = tcp_build_options(flags, options, sizeof(options));

	struct {
		ip4_hdr ip;
		tcp_hdr tcp;
		uint8_t options[kMaxTcpOptions];
	} frame = {};

	/* IPv4 */
	ip4_set_ihl_version(&frame.ip, 4, sizeof(ip4_hdr) / 4);
	frame.ip.tos = 0;
	frame.ip.tot_len = htons(sizeof(ip4_hdr) + sizeof(tcp_hdr) + opt_len + len);
	frame.ip.id = 0;
	frame.ip.frag_off = 0;
	frame.ip.ttl = 64;
	frame.ip.protocol = IPPROTO_TCP;
	frame.ip.saddr = flow->header.key4.daddr4;
	frame.ip.daddr = flow->header.key4.saddr4;
	frame.ip.check = 0;
	frame.ip.check = compute_checksum(&frame.ip, sizeof(ip4_hdr));

	/* TCP */
	frame.tcp.source = flow->header.key4.dport;
	frame.tcp.dest = flow->header.key4.sport;
	frame.tcp.seq = htonl(flow->seq_to_guest);
	frame.tcp.ack_seq = htonl(flow->ack_to_guest);
	tcp_set_doff(&frame.tcp, (sizeof(tcp_hdr) + opt_len) / 4);
	frame.tcp.flags = flags;
	size_t free_space = TCP_RX_BUF_CAP - flow->c_tcp_rx_len;
	frame.tcp.window = htons(free_space > 65535 ? 65535 : free_space);
	frame.tcp.check = 0;
	frame.tcp.urg_ptr = 0;

	pseudo_hdr4 phdr = {.saddr = flow->header.key4.daddr4,
	    .daddr = flow->header.key4.saddr4,
	    .zero = 0,
	    .protocol = IPPROTO_TCP,
	    .len = htons(sizeof(tcp_hdr) + opt_len + len)};

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(&frame.tcp, sizeof(tcp_hdr), sum);
	if (opt_len > 0) {
		sum = compute_checksum_part(options, opt_len, sum);
	}
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	frame.tcp.check = finalize_checksum(sum);

	if (opt_len > 0) {
		memcpy(frame.options, options, opt_len);
	}

	LOG_D("tcp_send_packet4: sending packet to guest: %s:%u -> %s:%u, flags=0x%x",
	    ip4_to_string(frame.ip.saddr).c_str(), ntohs(frame.tcp.source),
	    ip4_to_string(frame.ip.daddr).c_str(), ntohs(frame.tcp.dest), flags);

	return send_to_guest_v(ctx, &frame, sizeof(ip4_hdr) + sizeof(tcp_hdr) + opt_len, data, len);
}

bool tcp_send_packet6(
    Context* ctx, const TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet6: data length too large (%zu)", len);
		return false;
	}

	uint8_t options[kMaxTcpOptions] = {};
	size_t opt_len = tcp_build_options(flags, options, sizeof(options));

	struct {
		ip6_hdr ip;
		tcp_hdr tcp;
		uint8_t options[kMaxTcpOptions];
	} frame = {};

	/* IPv6 */
	frame.ip.vtf = htonl(0x60000000); /* Version 6 */
	frame.ip.payload_len = htons(sizeof(tcp_hdr) + opt_len + len);
	frame.ip.next_header = IPPROTO_TCP;
	frame.ip.hop_limit = 64;
	memcpy(frame.ip.saddr, flow->header.key6.daddr6, sizeof(frame.ip.saddr));
	memcpy(frame.ip.daddr, flow->header.key6.saddr6, sizeof(frame.ip.daddr));

	/* TCP */
	frame.tcp.source = flow->header.key6.dport;
	frame.tcp.dest = flow->header.key6.sport;
	frame.tcp.seq = htonl(flow->seq_to_guest);
	frame.tcp.ack_seq = htonl(flow->ack_to_guest);
	tcp_set_doff(&frame.tcp, (sizeof(tcp_hdr) + opt_len) / 4);
	frame.tcp.flags = flags;
	size_t free_space = TCP_RX_BUF_CAP - flow->c_tcp_rx_len;
	frame.tcp.window = htons(free_space > 65535 ? 65535 : free_space);
	frame.tcp.check = 0;
	frame.tcp.urg_ptr = 0;

	pseudo_hdr6 phdr = {
	    .saddr = {0},
	    .daddr = {0},
	    .len = htonl(sizeof(tcp_hdr) + opt_len + len),
	    .zeros = {0},
	    .next_header = IPPROTO_TCP,
	};
	memcpy(phdr.saddr, flow->header.key6.daddr6, sizeof(phdr.saddr));
	memcpy(phdr.daddr, flow->header.key6.saddr6, sizeof(phdr.daddr));

	uint32_t sum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	sum = compute_checksum_part(&frame.tcp, sizeof(tcp_hdr), sum);
	if (opt_len > 0) {
		sum = compute_checksum_part(options, opt_len, sum);
	}
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	frame.tcp.check = finalize_checksum(sum);

	if (opt_len > 0) {
		memcpy(frame.options, options, opt_len);
	}

	return send_to_guest_v(ctx, &frame, sizeof(ip6_hdr) + sizeof(tcp_hdr) + opt_len, data, len);
}

static inline bool tcp_send_packet(Context* ctx, const TcpFlow* flow, uint8_t flags,
    const uint8_t* data = nullptr, size_t len = 0) {
	if (flow->header.is_ipv6) {
		return tcp_send_packet6(ctx, flow, flags, data, len);
	} else {
		return tcp_send_packet4(ctx, flow, flags, data, len);
	}
}

static void tcp_rst_and_destroy(Context* ctx, TcpFlow* flow) {
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK)) {
		LOG_W("tcp_rst_and_destroy: failed to send RST packet");
	}
	tcp_destroy_flow(ctx, flow);
}

void tcp_destroy_flow(Context* ctx, TcpFlow* flow) {
	if (!flow->header.active) {
		return;
	}

	if (flow->header.host_fd != -1) {
		monitor::removeFd(flow->header.host_fd);
		close(flow->header.host_fd);
		set_tcp_flow_by_fd(ctx, flow->header.host_fd, nullptr);
		flow->header.host_fd = -1;
	}

	if (flow->header.is_ipv6) {
		if (ctx->num_c_ipv6_tcp_flows > 0) {
			ctx->num_c_ipv6_tcp_flows--;
		}
	} else {
		if (ctx->num_c_ipv4_tcp_flows > 0) {
			ctx->num_c_ipv4_tcp_flows--;
		}
	}

	/* Free heap-allocated buffers via RAII */
	flow->c_tcp_tx_buf.reset();
	flow->c_tcp_rx_buf.reset();
	flow->c_proxy_rx_buf.reset();

	/* Mark inactive */
	flow->header.active = false;
}

void push_to_guest(Context* ctx, TcpFlow* flow) {
	if (flow->tcp_state != TcpState::ESTABLISHED && flow->tcp_state != TcpState::CLOSE_WAIT) {
		return;
	}

	/* Max TCP payload per TUN frame: MTU minus IP and TCP headers */
	size_t max_seg = NSTUN_MTU - (flow->header.is_ipv6 ? sizeof(ip6_hdr) : sizeof(ip4_hdr)) -
			 sizeof(tcp_hdr);

	for (;;) {
		int32_t in_flight = flow->seq_to_guest - flow->ack_from_guest;
		int32_t available = flow->c_tcp_tx_len - flow->tx_acked_offset;

		if (in_flight < 0) {
			/* Guest acked future data? Reset flight */
			flow->seq_to_guest = flow->ack_from_guest;
			in_flight = 0;
		}
		if (in_flight >= available) {
			if (flow->host_eof && available == 0) {
				if (!flow->fin_sent) {
					/* Stream fully flushed and host closed write-end */
					if (!tcp_send_packet(ctx, flow,
						NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_ACK)) {
						LOG_W("push_to_guest: failed to send FIN packet");
					} else {
						flow->seq_to_guest++;
						flow->fin_sent = true;
						if (flow->tcp_state == TcpState::ESTABLISHED) {
							flow->tcp_state = TcpState::FIN_WAIT_1;
						}
					}
				}
			}
			return; /* Everything is in flight */
		}

		size_t to_send = available - in_flight;
		if (to_send > max_seg) {
			to_send = max_seg;
		}

		const uint8_t* data = flow->c_tcp_tx_buf.get() + flow->tx_acked_offset + in_flight;
		uint8_t flags = NSTUN_TCP_FLAG_ACK;
		if (to_send >= static_cast<size_t>(available - in_flight)) {
			flags |= NSTUN_TCP_FLAG_PSH;
		}

		if (!tcp_send_packet(ctx, flow, flags, data, to_send)) {
			LOG_W("push_to_guest: failed to send packet");
			break;
		}
		flow->seq_to_guest += to_send;
	}
}

/* Returns true if the flow was destroyed (caller must not use flow afterward) */
bool flush_to_host(Context* ctx, TcpFlow* flow) {
	if (flow->rx_sent_offset >= flow->c_tcp_rx_len) {
		return false;
	}

	size_t to_send = flow->c_tcp_rx_len - flow->rx_sent_offset;
	ssize_t written = TEMP_FAILURE_RETRY(send(flow->header.host_fd,
	    flow->c_tcp_rx_buf.get() + flow->rx_sent_offset, to_send, MSG_NOSIGNAL));

	if (written > 0) {
		flow->rx_sent_offset += written;
		if (flow->rx_sent_offset >= flow->c_tcp_rx_len) {
			flow->c_tcp_rx_len = 0;
			flow->rx_sent_offset = 0;
		} else if (flow->rx_sent_offset > 0) {
			buffer_consume(
			    flow->c_tcp_rx_buf.get(), &flow->c_tcp_rx_len, flow->rx_sent_offset);
			flow->rx_sent_offset = 0;
		}

		/* We made progress, remove EPOLLOUT if empty */
		if (flow->c_tcp_rx_len == 0 && flow->epoll_out_registered) {
			flow->epoll_out_registered = false;
			if (!tcp_update_host_mask(flow)) {
				PLOG_E("tcp_update_host_mask() failed");
				tcp_rst_and_destroy(ctx, flow);
				return true;
			}
		}

		if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
			LOG_W("flush_to_host: failed to send ACK");
		}
		return false;

	} else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		/* Apply backpressure, register EPOLLOUT */
		if (!flow->epoll_out_registered) {
			flow->epoll_out_registered = true;
			if (!tcp_update_host_mask(flow)) {
				PLOG_E("tcp_update_host_mask() failed");
				tcp_rst_and_destroy(ctx, flow);
				return true;
			}
		}
		return false;
	} else {
		/* Terminal error, RST the guest */
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
}

/* --- state handlers ------------------------------------ */

static void handle_socks5_init_host(Context* ctx, TcpFlow* flow, int fd) {
	constexpr size_t expected_len = 2; /* SOCKS5 auth reply is 2 bytes */
	if (flow->c_proxy_rx_len < expected_len) {
		ssize_t recv_len =
		    TEMP_FAILURE_RETRY(recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len,
			expected_len - flow->c_proxy_rx_len, MSG_DONTWAIT));
		if (recv_len == 0) {
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			tcp_rst_and_destroy(ctx, flow);
			return;
		}

		flow->c_proxy_rx_len += recv_len;
	}
	if (flow->c_proxy_rx_len < expected_len) {
		return;
	}

	if (!nstun::parse_socks5_auth_reply(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len)) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_proxy_rx_len = 0;
	flow->tcp_state = TcpState::SOCKS5_CONNECTING;

	uint8_t addr_buf[16];
	if (flow->header.is_ipv6) {
		memcpy(addr_buf, flow->header.key6.daddr6, 16);
	} else {
		memcpy(addr_buf, &flow->header.key4.daddr4, 4);
	}
	uint16_t port = flow->header.is_ipv6 ? flow->header.key6.dport : flow->header.key4.dport;

	if (nstun::send_socks5_connect(fd, addr_buf, port, flow->header.is_ipv6) < 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
}

static bool handle_socks5_init_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	/* Guest data received during proxy negotiation - buffer it, don't forward yet. */
	if (!append_tcp_rx(flow, data, len)) {
		LOG_E("tcp_rx_buf overflow in handle_socks5_init_guest");
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
	return false;
}

static void handle_socks5_connecting_host(Context* ctx, TcpFlow* flow, int fd) {
	/*
	 * Accumulate the full SOCKS5 CONNECT reply.  The reply length depends
	 * on the ATYP field (byte [3]):
	 *   0x01 (IPv4):   10 bytes  (sizeof(socks5_req))
	 *   0x04 (IPv6):   22 bytes  (sizeof(socks5_req6))
	 *   0x03 (domain): 5 + domain_len + 2
	 * We need at least 4 bytes to know ATYP, then possibly more.
	 */

	/* Try to read more data into the proxy rx buffer */
	size_t avail = PROXY_RX_BUF_CAP - flow->c_proxy_rx_len;
	if (avail == 0) {
		LOG_E("Proxy RX buffer overflow in handle_socks5_connecting_host");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len, avail, MSG_DONTWAIT));
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_proxy_rx_len += recv_len;
	size_t current_len = flow->c_proxy_rx_len;

	/* Need at least 4 bytes to determine ATYP */
	if (current_len < 4) {
		return;
	}

	/* Determine full expected length based on ATYP */
	size_t expected_len;
	uint8_t atyp = flow->c_proxy_rx_buf[3];
	switch (atyp) {
	case SOCKS5_ATYP_IPV4:
		expected_len = sizeof(socks5_req);
		break;
	case SOCKS5_ATYP_IPV6:
		expected_len = sizeof(socks5_req6);
		break;
	case SOCKS5_ATYP_DOMAIN:
		if (current_len < 5) {
			return; /* Need 5th byte to know domain length */
		}
		expected_len = 5 + flow->c_proxy_rx_buf[4] + 2;
		break;
	default:
		LOG_W("Unknown SOCKS5 ATYP: %u", atyp);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (current_len < expected_len) {
		return; /* Wait for more data */
	}

	/* Validate SOCKS5 response */
	uint8_t rep_ver = flow->c_proxy_rx_buf[0];
	uint8_t rep_cmd = flow->c_proxy_rx_buf[1];
	if (rep_ver != SOCKS5_VERSION || rep_cmd != SOCKS5_REP_SUCCESS) {
		LOG_W("SOCKS5 connection failed: ver=%u rep=%u", rep_ver, rep_cmd);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	/*
	 * Full response received.  Any bytes beyond expected_len are tunnelled
	 * payload from the remote server — save them in the TX buffer so they
	 * get pushed to the guest after the SYN-ACK.
	 */
	if (current_len > expected_len) {
		if (!append_tcp_tx(flow, flow->c_proxy_rx_buf.get() + expected_len,
			current_len - expected_len)) {
			LOG_E("tcp_tx_buf overflow in handle_socks5_connecting_host");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
	}
	flow->c_proxy_rx_len = 0;
	flow->tcp_state = TcpState::ESTABLISHED;
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_socks5_connecting_host: failed to send SYN/ACK");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	flow->seq_to_guest++;

	/* If there was piggybacked tunnel data, push it now */
	if (flow->c_tcp_tx_len > 0) {
		push_to_guest(ctx, flow);
	}
}

static void handle_http_connect_wait_host(Context* ctx, TcpFlow* flow, int fd) {
	size_t end_of_headers = 0;

	size_t avail = PROXY_RX_BUF_CAP - flow->c_proxy_rx_len;
	if (avail == 0) {
		LOG_E("HTTP proxy response too long");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	size_t to_read = std::min((size_t)4096, avail);
	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len, to_read, MSG_DONTWAIT));
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tcp_rst_and_destroy(ctx, flow);
		}
		return;
	}

	flow->c_proxy_rx_len += recv_len;

	end_of_headers =
	    nstun::find_end_of_headers(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len);
	if (end_of_headers == 0) {
		if (flow->c_proxy_rx_len >= PROXY_RX_BUF_CAP) {
			LOG_E("HTTP proxy response too long without headers end");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		return; /* Wait for more data */
	}

	if (!nstun::parse_http_connect_reply(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len)) {
		LOG_W("HTTP CONNECT failed: %.*s",
		    static_cast<int>(std::min(end_of_headers, static_cast<size_t>(64))),
		    flow->c_proxy_rx_buf.get());
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	/* Anything after the headers is tunnelled payload - forward it */
	if (flow->c_proxy_rx_len > end_of_headers) {
		if (!append_tcp_tx(flow, flow->c_proxy_rx_buf.get() + end_of_headers,
			flow->c_proxy_rx_len - end_of_headers)) {
			LOG_E("tcp_tx_buf overflow in handle_http_connect_wait_host");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
	}
	/* Release proxy negotiation buffer - no longer needed */
	flow->c_proxy_rx_len = 0;

	flow->tcp_state = TcpState::ESTABLISHED;
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_http_connect_wait_host: failed to send SYN/ACK");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	flow->seq_to_guest++;

	if (flow->c_tcp_tx_len > 0) {
		push_to_guest(ctx, flow);
	}
}

static void handle_data_transfer_host(Context* ctx, TcpFlow* flow, int fd) {
	size_t avail = TCP_TX_BUF_CAP - flow->c_tcp_tx_len;
	if (avail == 0) {
		/* Buffer full, apply backpressure by stopping reading */
		if (!flow->epoll_in_disabled) {
			flow->epoll_in_disabled = true;
			if (!tcp_update_host_mask(flow)) {
				PLOG_E("tcp_update_host_mask() failed");
				tcp_rst_and_destroy(ctx, flow);
				return;
			}
		}
		return;
	}

	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_tcp_tx_buf.get() + flow->c_tcp_tx_len, avail, MSG_DONTWAIT));
	if (recv_len == 0) {
		handle_host_tcp_data_eof(ctx, flow, fd);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_tcp_tx_len += recv_len;

	if (flow->tcp_state != TcpState::SYN_SENT) {
		push_to_guest(ctx, flow);
	}
}

static bool handle_data_transfer_guest(
    Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	if (!append_tcp_rx(flow, data, len)) {
		LOG_E("tcp_rx_buf overflow in handle_data_transfer_guest");
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
	return flush_to_host(ctx, flow);
}

/*
 * Drain and discard any residual host data for flows in CLOSING/TIME_WAIT.
 * These states mean both sides have already signalled EOF, so any stale
 * epoll events (buffered kernel data, late EPOLLIN) must not crash the
 * process. We read and discard a chunk (without looping to avoid event starvation).
 */
static void handle_draining_state_host(Context* ctx, TcpFlow* flow, int fd) {
	uint8_t discard[64];
	ssize_t n = TEMP_FAILURE_RETRY(recv(fd, discard, sizeof(discard), MSG_DONTWAIT));
	if (n == 0) {
		LOG_D("EOF in draining state for fd %d, destroying flow", fd);
		tcp_destroy_flow(ctx, flow);
	} else if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_W("recv in handle_draining_state_host");
		}
	}
}

static bool handle_draining_state_guest(
    Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	/* Discard any late guest data in terminal states */
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_draining_state_guest: failed to send ACK");
	}
	return false;
}

static const TcpStateHandlers kStateTable[] = {
    [static_cast<int>(TcpState::SYN_SENT)] = {.on_host_data = handle_data_transfer_host,
	.on_guest_packet = handle_data_transfer_guest},
    [static_cast<int>(TcpState::SOCKS5_INIT)] = {.on_host_data = handle_socks5_init_host,
	.on_guest_packet = handle_socks5_init_guest},
    [static_cast<int>(TcpState::SOCKS5_CONNECTING)] = {.on_host_data =
							   handle_socks5_connecting_host,
	.on_guest_packet = handle_socks5_init_guest},
    [static_cast<int>(TcpState::HTTP_CONNECT_WAIT)] = {.on_host_data =
							   handle_http_connect_wait_host,
	.on_guest_packet = handle_socks5_init_guest},
    [static_cast<int>(TcpState::ESTABLISHED)] = {.on_host_data = handle_data_transfer_host,
	.on_guest_packet = handle_data_transfer_guest},
    [static_cast<int>(TcpState::FIN_WAIT_1)] = {.on_host_data = handle_data_transfer_host,
	.on_guest_packet = handle_data_transfer_guest},
    [static_cast<int>(TcpState::FIN_WAIT_2)] = {.on_host_data = handle_data_transfer_host,
	.on_guest_packet = handle_data_transfer_guest},
    [static_cast<int>(TcpState::CLOSING)] = {.on_host_data = handle_draining_state_host,
	.on_guest_packet = handle_draining_state_guest},
    [static_cast<int>(TcpState::TIME_WAIT)] = {.on_host_data = handle_draining_state_host,
	.on_guest_packet = handle_draining_state_guest},
    [static_cast<int>(TcpState::CLOSE_WAIT)] = {.on_host_data = handle_data_transfer_host,
	.on_guest_packet = handle_data_transfer_guest},
};

static bool tcp_should_reenable_host_rx(const TcpFlow* flow) {
	return flow->epoll_in_disabled && !flow->host_eof &&
	       (flow->c_tcp_tx_len - flow->tx_acked_offset < TCP_TX_BUF_CAP / 2);
}

static void tcp_process_ack(
    Context* ctx, TcpFlow* flow, const tcp_hdr* tcp, uint32_t ack, size_t data_len) {
	if (flow->tcp_state == TcpState::SYN_SENT) {
		flow->tcp_state = TcpState::ESTABLISHED;
		flow->ack_from_guest = ack;
		flow->syn_acked = true;
		push_to_guest(ctx, flow);
	} else {
		int32_t acked_bytes = ack - flow->ack_from_guest;
		if (acked_bytes > 0) {
			flow->ack_from_guest = ack;
			if (!flow->syn_acked) {
				flow->syn_acked = true;
				acked_bytes--;
			}
			if (flow->fin_sent && !flow->fin_acked && ack == flow->seq_to_guest) {
				flow->fin_acked = true;
				acked_bytes--;
			}
			size_t advance = (acked_bytes > 0) ? static_cast<size_t>(acked_bytes) : 0;
			flow->tx_acked_offset += advance;

			size_t erase_len = flow->tx_acked_offset;
			if (erase_len > flow->c_tcp_tx_len) {
				erase_len = flow->c_tcp_tx_len;
			}

			if (erase_len > 0) {
				buffer_consume(
				    flow->c_tcp_tx_buf.get(), &flow->c_tcp_tx_len, erase_len);
				flow->tx_acked_offset -= erase_len;
			}

			if (tcp_should_reenable_host_rx(flow)) {
				flow->epoll_in_disabled = false;
				if (!tcp_update_host_mask(flow)) {
					PLOG_E("tcp_update_host_mask() failed");
					tcp_rst_and_destroy(ctx, flow);
					return;
				}
			}

			push_to_guest(ctx, flow);
		} else if (acked_bytes == 0 && data_len == 0 &&
			   !(tcp->flags &
			       (NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_RST))) {
			flow->seq_to_guest = flow->ack_from_guest;
			push_to_guest(ctx, flow);
		}
	}

	if (flow->tcp_state == TcpState::FIN_WAIT_1 && ack == flow->seq_to_guest) {
		flow->tcp_state = TcpState::FIN_WAIT_2;
	}
}

static void tcp_process_fin(Context* ctx, TcpFlow* flow, const tcp_hdr* tcp) {
	LOG_D("Received FIN from guest");
	flow->seq_from_guest++;
	flow->ack_to_guest = flow->seq_from_guest;

	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
		LOG_W("tcp_process_fin: failed to send ACK to guest");
	}

	shutdown(flow->header.host_fd, SHUT_WR);
	flow->guest_eof = true;

	switch (flow->tcp_state) {
	case TcpState::ESTABLISHED:
		flow->tcp_state = TcpState::CLOSE_WAIT;
		break;
	case TcpState::FIN_WAIT_1:
		flow->tcp_state = TcpState::CLOSING;
		break;
	case TcpState::FIN_WAIT_2:
		flow->tcp_state = TcpState::TIME_WAIT;
		break;
	default:
		break;
	}

	push_to_guest(ctx, flow);
}

static bool tcp_dispatch_guest_packet(
    Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	size_t state_idx = static_cast<size_t>(flow->tcp_state);
	if (state_idx < sizeof(kStateTable) / sizeof(kStateTable[0])) {
		if (kStateTable[state_idx].on_guest_packet) {
			return kStateTable[state_idx].on_guest_packet(ctx, flow, data, len);
		}
	}
	return false;
}

static bool tcp_process_valid_guest_data(
    Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	flow->seq_from_guest += len;
	flow->ack_to_guest = flow->seq_from_guest;

	return tcp_dispatch_guest_packet(ctx, flow, data, len);
}

static bool tcp_handle_guest_data_payload(Context* ctx, TcpFlow* flow, uint32_t seq,
    const uint8_t* data, size_t data_len, bool* data_processed) {
	*data_processed = false;
	int32_t diff = seq - flow->ack_to_guest;
	int32_t end_diff = (seq + static_cast<uint32_t>(data_len)) - flow->ack_to_guest;

	if (diff <= 0 && end_diff > 0) {
		uint32_t overlap = flow->ack_to_guest - seq;
		const uint8_t* new_data = data + overlap;
		size_t new_data_len = data_len - overlap;

		if (flow->c_tcp_rx_len + new_data_len > TCP_RX_BUF_CAP) {
			LOG_D("TCP rx_buffer full (DoS protection), dropping");
			return false;
		}

		*data_processed = true;
		return tcp_process_valid_guest_data(ctx, flow, new_data, new_data_len);
	}
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
		LOG_W("tcp_handle_guest_data: failed to send ACK");
	}
	return false;
}

static void tcp_process_active_packet(Context* ctx, TcpFlow* flow, const tcp_hdr* tcp, uint32_t seq,
    uint32_t ack, const uint8_t* data, size_t data_len) {
	bool data_processed = false;
	if (data_len > 0) {
		if (tcp_handle_guest_data_payload(
			ctx, flow, seq, data, data_len, &data_processed)) {
			return;
		}
	}

	if (tcp->flags & NSTUN_TCP_FLAG_ACK) {
		tcp_process_ack(ctx, flow, tcp, ack, data_len);
	}

	if ((tcp->flags & NSTUN_TCP_FLAG_FIN) && (data_len == 0 || data_processed)) {
		tcp_process_fin(ctx, flow, tcp);
	}
}

static bool handle_inbound_syn_ack(Context* ctx, TcpFlow* flow, uint32_t seq, uint32_t ack) {
	flow->tcp_state = TcpState::ESTABLISHED;
	flow->ack_from_guest = ack;
	flow->seq_from_guest = seq + 1;
	flow->ack_to_guest = flow->seq_from_guest;
	flow->syn_acked = true;

	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_inbound_syn_ack: failed to send ACK");
	}

	if (flow->c_tcp_tx_len > 0) {
		push_to_guest(ctx, flow);
	}

	if (flow->epoll_in_disabled) {
		flow->epoll_in_disabled = false;
		if (!tcp_update_host_mask(flow)) {
			PLOG_E("tcp_update_host_mask() failed");
			tcp_rst_and_destroy(ctx, flow);
			return true;
		}
	}
	return false;
}

static inline bool tcp_state_is_active(TcpState state) {
	switch (state) {
	case TcpState::ESTABLISHED:
	case TcpState::FIN_WAIT_1:
	case TcpState::FIN_WAIT_2:
	case TcpState::SYN_SENT:
	case TcpState::CLOSE_WAIT:
		return true;
	default:
		return false;
	}
}

static void tcp_process_data(Context* ctx, TcpFlow* flow, const tcp_hdr* tcp,
    const uint8_t* payload, size_t payload_len, uint8_t doff) {
	if (payload_len < doff) {
		LOG_W("TCP packet too short for data offset: size %zu < offset %u", payload_len,
		    doff);
		return;
	}
	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	if (flow->inbound && flow->tcp_state == TcpState::SYN_SENT &&
	    (tcp->flags & NSTUN_TCP_FLAG_SYN) && (tcp->flags & NSTUN_TCP_FLAG_ACK)) {
		handle_inbound_syn_ack(ctx, flow, seq, ack);
		return;
	}

	if (tcp->flags & NSTUN_TCP_FLAG_RST) {
		LOG_D("Received RST from guest");
		tcp_destroy_flow(ctx, flow);
		return;
	}

	if (tcp_state_is_active(flow->tcp_state)) {
		const uint8_t* data = payload + doff;
		size_t data_len = payload_len - doff;

		/* Defense-in-depth: cap to MTU to prevent int32_t overflow in seq arithmetic */
		if (data_len > NSTUN_MTU) {
			return;
		}

		tcp_process_active_packet(ctx, flow, tcp, seq, ack, data, data_len);
	}
}

/* --- flow initialization ------------------------------- */

/*
 * Initialize all common TcpFlow fields for a new outbound connection.
 * Callers set key4/key6 themselves (type-specific) before calling this.
 *
 * seq_from_guest: the SYN sequence number from the guest + 1.
 */
static void init_outbound_flow_common(
    TcpFlow* flow, int fd, bool is_ipv6, ProxyMode proxy, uint32_t seq_from_guest) {
	flow->header.host_fd = fd;
	flow->header.is_ipv6 = is_ipv6;
	flow->tcp_state = TcpState::SYN_SENT;
	flow->proxy_mode = proxy;
	flow->host_eof = false;
	flow->guest_eof = false;
	flow->fin_sent = false;
	flow->syn_acked = false;
	flow->fin_acked = false;
	uint32_t isn = generate_isn();
	flow->seq_to_guest = isn;
	flow->seq_from_guest = seq_from_guest;
	flow->ack_to_guest = seq_from_guest;
	flow->ack_from_guest = flow->seq_to_guest; /* ACK our own SYN */
	flow->tx_acked_offset = 0;
	flow->rx_sent_offset = 0;
	flow->epoll_out_registered = true;
	flow->epoll_in_disabled = false;
	flow->inbound = false;
	flow->header.last_active = time(nullptr);
}

/*
 * Attempt a non-blocking connect() and dispatch the result.
 *
 * - Immediate success (loopback / same-host): calls handle_host_tcp_connected.
 * - EINPROGRESS: returns; EPOLLOUT will fire when the connection completes.
 * - Any other error: RSTs the guest and destroys the flow.
 */
static bool tcp_do_connect(
    Context* ctx, TcpFlow* flow, int fd, const struct sockaddr* addr, socklen_t addrlen) {
	int ret = connect(fd, addr, addrlen);
	if (ret == 0) {
		handle_host_tcp_connected(ctx, flow, fd);
		return true;
	} else if (errno == EINPROGRESS || errno == EINTR) {
		/* Normal non-blocking result - EPOLLOUT will fire on completion */
		return true;
	} else {
		PLOG_E("connect() failed");
		return false;
	}
}
static bool init_tcp_flow_zero(TcpFlow* flow) {
	/* Preserve existing allocations for reuse */
	auto old_tx = std::move(flow->c_tcp_tx_buf);
	auto old_rx = std::move(flow->c_tcp_rx_buf);
	auto old_proxy = std::move(flow->c_proxy_rx_buf);

	/* Zero all POD fields and reset unique_ptrs */
	*flow = TcpFlow{};
	flow->header.type = FlowType::TCP;
	flow->header.host_fd = -1;
	flow->tcp_state = TcpState::SYN_SENT;
	flow->proxy_mode = ProxyMode::NONE;

	/* Reuse old allocations if available, otherwise allocate */
	flow->c_tcp_tx_buf =
	    old_tx ? std::move(old_tx)
		   : std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[TCP_TX_BUF_CAP]);
	flow->c_tcp_rx_buf =
	    old_rx ? std::move(old_rx)
		   : std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[TCP_RX_BUF_CAP]);
	flow->c_proxy_rx_buf =
	    old_proxy ? std::move(old_proxy)
		      : std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[PROXY_RX_BUF_CAP]);

	if (!flow->c_tcp_tx_buf || !flow->c_tcp_rx_buf || !flow->c_proxy_rx_buf) {
		flow->c_tcp_tx_buf.reset();
		flow->c_tcp_rx_buf.reset();
		flow->c_proxy_rx_buf.reset();
		return false;
	}
	return true;
}

static TcpFlow* find_v4_tcp_flow(Context* ctx, const FlowKey4& key) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; i++) {
		TcpFlow& flow = ctx->c_ipv4_tcp_flows[i];
		if (flow.header.active) {
			if (memcmp(&flow.header.key4, &key, sizeof(key)) == 0) {
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv4_tcp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static TcpFlow* alloc_v4_tcp_flow(Context* ctx, const FlowKey4& key) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; i++) {
		if (!ctx->c_ipv4_tcp_flows[i].header.active) {
			TcpFlow* flow = &ctx->c_ipv4_tcp_flows[i];
			if (!init_tcp_flow_zero(flow)) {
				return nullptr;
			}
			flow->header.active = true;
			flow->header.key4 = key;
			ctx->num_c_ipv4_tcp_flows++;
			return flow;
		}
	}
	return nullptr;
}

static TcpFlow* find_v6_tcp_flow(Context* ctx, const FlowKey6& key) {
	size_t active_seen = 0;
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; i++) {
		TcpFlow& flow = ctx->c_ipv6_tcp_flows[i];
		if (flow.header.active) {
			if (memcmp(&flow.header.key6, &key, sizeof(key)) == 0) {
				return &flow;
			}
			active_seen++;
			if (active_seen >= ctx->num_c_ipv6_tcp_flows) {
				break;
			}
		}
	}
	return nullptr;
}

static TcpFlow* alloc_v6_tcp_flow(Context* ctx, const FlowKey6& key) {
	for (size_t i = 0; i < NSTUN_MAX_FLOWS; i++) {
		if (!ctx->c_ipv6_tcp_flows[i].header.active) {
			TcpFlow* flow = &ctx->c_ipv6_tcp_flows[i];
			if (!init_tcp_flow_zero(flow)) {
				return nullptr;
			}
			flow->header.active = true;
			flow->header.key6 = key;
			ctx->num_c_ipv6_tcp_flows++;
			return flow;
		}
	}
	return nullptr;
}

static TcpFlow* create_outbound_flow4(
    Context* ctx, const ip4_hdr* ip, const tcp_hdr* tcp, const FlowKey4& key4, uint32_t seq) {
	uint16_t guest_port = ntohs(tcp->source);
	uint16_t dest_port = ntohs(tcp->dest);
	int opt = 1;
	struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);

	RuleResult rule = evaluate_rules4(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP, ip->saddr,
	    ip->daddr, guest_port, dest_port);

	if (rule.action == NSTUN_ACTION_DROP) {
		LOG_D("TCP connect to %s:%u dropped by policy", ip4_to_string(ip->daddr).c_str(),
		    dest_port);
		return nullptr;
	}
	if (rule.action == NSTUN_ACTION_REJECT) {
		LOG_D("TCP connect to %s:%u rejected by policy", ip4_to_string(ip->daddr).c_str(),
		    dest_port);
		tcp_send_rst4(ctx, key4, 0, seq + 1);
		return nullptr;
	}

	TcpFlow* flow = alloc_v4_tcp_flow(ctx, key4);
	if (!flow) {
		LOG_W("Maximum number of TCP flows reached, dropping");
		tcp_send_rst4(ctx, key4, 0, seq + 1);
		return nullptr;
	}

	bool success = false;
	defer {
		if (!success) {
			tcp_send_rst4(ctx, key4, 0, seq + 1);
			tcp_destroy_flow(ctx, flow);
		}
	};

	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM)");
		return nullptr;
	}

	init_outbound_flow_common(
	    flow, fd, /*is_ipv6=*/false, proxy_mode_from_action(rule.action), seq + 1);

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
		PLOG_W("setsockopt(TCP_NODELAY)");
	}

	if (rule.redirect_ip4 && rule.redirect_port) {
		dest_addr.sin_addr.s_addr = rule.redirect_ip4;
		dest_addr.sin_port = htons(rule.redirect_port);
		LOG_D("Redirecting TCP flow guest %u to host %s:%u via policy (fd=%d)", guest_port,
		    ip4_to_string(rule.redirect_ip4).c_str(), rule.redirect_port, fd);
	} else {
		dest_addr.sin_addr.s_addr = key4.daddr4;
		dest_addr.sin_port = tcp->dest;
		LOG_D("New TCP flow guest %u -> host %s:%u (fd=%d)", guest_port,
		    ip4_to_string(key4.daddr4).c_str(), dest_port, fd);
	}

	if (!monitor::addFd(fd, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, host_callback, ctx)) {
		PLOG_E("monitor::addFd()");
		return nullptr;
	}

	if (!set_tcp_flow_by_fd(ctx, fd, flow)) {
		LOG_E("FD %d out of bounds for c_tcp_flows_by_fd", fd);
		return nullptr;
	}

	if (!tcp_do_connect(
		ctx, flow, fd, reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr))) {
		return nullptr;
	}

	success = true;
	return flow;
}

static TcpFlow* create_outbound_flow6(
    Context* ctx, const ip6_hdr* ip, const tcp_hdr* tcp, const FlowKey6& key6, uint32_t seq) {
	uint16_t guest_port = ntohs(tcp->source);
	uint16_t dest_port = ntohs(tcp->dest);
	int opt = 1;

	RuleResult rule = evaluate_rules6(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP, ip->saddr,
	    ip->daddr, guest_port, dest_port);

	if (rule.action == NSTUN_ACTION_DROP) {
		LOG_D("IPv6 TCP connect to port %u dropped by policy", dest_port);
		return nullptr;
	}
	if (rule.action == NSTUN_ACTION_REJECT) {
		LOG_D("IPv6 TCP connect to port %u rejected by policy", dest_port);
		tcp_send_rst6(ctx, key6, 0, seq + 1);
		return nullptr;
	}

	TcpFlow* flow = alloc_v6_tcp_flow(ctx, key6);
	if (!flow) {
		LOG_W("Maximum number of IPv6 TCP flows reached, dropping");
		tcp_send_rst6(ctx, key6, 0, seq + 1);
		return nullptr;
	}

	bool success = false;
	defer {
		if (!success) {
			tcp_send_rst6(ctx, key6, 0, seq + 1);
			tcp_destroy_flow(ctx, flow);
		}
	};

	bool use_proxy =
	    (rule.action == NSTUN_ACTION_ENCAP_SOCKS5 || rule.action == NSTUN_ACTION_ENCAP_CONNECT);

	int family = use_proxy ? AF_INET : AF_INET6;
	int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		PLOG_E("socket() IPv6 TCP outbound");
		return nullptr;
	}

	init_outbound_flow_common(
	    flow, fd, /*is_ipv6=*/true, proxy_mode_from_action(rule.action), seq + 1);

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
		PLOG_W("setsockopt(TCP_NODELAY)");
	}

	if (!monitor::addFd(fd, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, host_callback, ctx)) {
		PLOG_E("monitor::addFd() for IPv6 TCP failed");
		return nullptr;
	}

	if (!set_tcp_flow_by_fd(ctx, fd, flow)) {
		LOG_E("FD %d out of bounds for c_tcp_flows_by_fd", fd);
		return nullptr;
	}

	if (use_proxy) {
		struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
		dest_addr.sin_addr.s_addr = rule.redirect_ip4;
		dest_addr.sin_port = htons(rule.redirect_port);
		LOG_D("Connecting IPv6 TCP flow guest %u to IPv4 proxy port %u (fd=%d)", guest_port,
		    rule.redirect_port, fd);
		if (!tcp_do_connect(ctx, flow, fd, reinterpret_cast<struct sockaddr*>(&dest_addr),
			sizeof(dest_addr))) {
			return nullptr;
		}
	} else {
		struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);
		if (rule.has_redirect_ip6 && rule.redirect_port) {
			memcpy(
			    &dest_addr.sin6_addr, rule.redirect_ip6, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(rule.redirect_port);
			LOG_D("Redirecting IPv6 TCP flow guest %u to %s:%u via policy (fd=%d)",
			    guest_port, ip6_to_string(rule.redirect_ip6).c_str(),
			    rule.redirect_port, fd);
		} else {
			memcpy(&dest_addr.sin6_addr, key6.daddr6, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = tcp->dest;
			LOG_D("New IPv6 TCP flow guest %u -> host %s:%u (fd=%d)", guest_port,
			    ip6_to_string(key6.daddr6).c_str(), dest_port, fd);
		}
		if (!tcp_do_connect(ctx, flow, fd, reinterpret_cast<struct sockaddr*>(&dest_addr),
			sizeof(dest_addr))) {
			return nullptr;
		}
	}

	success = true;
	return flow;
}

/* --- entry points -------------------------------------- */

void handle_tcp4(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t payload_len) {
	if (payload_len < sizeof(tcp_hdr)) {
		return;
	}

	tcp_hdr tcp;
	memcpy(&tcp, payload, sizeof(tcp));
	uint8_t doff = tcp_doff(&tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > payload_len) {
		return;
	}

	/* Validate TCP checksum */
	pseudo_hdr4 phdr = {.saddr = ip->saddr,
	    .daddr = ip->daddr,
	    .zero = 0,
	    .protocol = IPPROTO_TCP,
	    .len = htons(payload_len)};
	uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	csum = compute_checksum_part(payload, payload_len, csum);
	if (finalize_checksum(csum) != 0) {
		LOG_D("Invalid IPv4 TCP checksum, dropping");
		return;
	}

	FlowKey4 key4 = {ip->saddr, ip->daddr, tcp.source, tcp.dest};
	LOG_D("handle_tcp4: key4={saddr=%s, daddr=%s, sport=%u, dport=%u}",
	    ip4_to_string(key4.saddr4).c_str(), ip4_to_string(key4.daddr4).c_str(),
	    ntohs(key4.sport), ntohs(key4.dport));

	uint32_t seq = ntohl(tcp.seq);
	uint32_t ack = ntohl(tcp.ack_seq);

	TcpFlow* flow = find_v4_tcp_flow(ctx, key4);
	LOG_D("handle_tcp4: flow found=%p", flow);

	if (flow) {
		flow->header.last_active = time(nullptr);
	} else {
		if (!(tcp.flags & NSTUN_TCP_FLAG_SYN)) {
			return;
		}
		flow = create_outbound_flow4(ctx, ip, &tcp, key4, seq);
		if (!flow) {
			return;
		}
		return;
	}

	tcp_process_data(ctx, flow, &tcp, payload, payload_len, doff);
}

void handle_host_tcp_connected(Context* ctx, TcpFlow* flow, int fd) {
	int err = 0;
	socklen_t errlen = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		PLOG_E("getsockopt(SO_ERROR)");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (err != 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->epoll_out_registered = false;
	if (!tcp_update_host_mask(flow)) {
		PLOG_E("tcp_update_host_mask() failed");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	switch (flow->proxy_mode) {
	case ProxyMode::NONE:
		flow->tcp_state = TcpState::ESTABLISHED;
		if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK)) {
			LOG_W("handle_host_tcp_connected: failed to send SYN/ACK");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		flow->seq_to_guest++;
		return;

	case ProxyMode::HTTP_CONNECT: {
		flow->tcp_state = TcpState::HTTP_CONNECT_WAIT;
		uint8_t addr_buf[16];
		if (flow->header.is_ipv6) {
			memcpy(addr_buf, flow->header.key6.daddr6, 16);
		} else {
			memcpy(addr_buf, &flow->header.key4.daddr4, 4);
		}
		uint16_t port =
		    flow->header.is_ipv6 ? flow->header.key6.dport : flow->header.key4.dport;
		if (nstun::send_http_connect(fd, addr_buf, port, flow->header.is_ipv6) < 0) {
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}

	case ProxyMode::SOCKS5:
		flow->tcp_state = TcpState::SOCKS5_INIT;
		if (nstun::send_socks5_greeting(fd) < 0) {
			PLOG_E("send() SOCKS5 greeting");
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}
}

void handle_host_tcp_data(Context* ctx, TcpFlow* flow, int fd) {
	size_t state_idx = static_cast<size_t>(flow->tcp_state);
	if (state_idx >= sizeof(kStateTable) / sizeof(kStateTable[0])) {
		LOG_W("Invalid TCP state: %zu", state_idx);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (kStateTable[state_idx].on_host_data) {
		kStateTable[state_idx].on_host_data(ctx, flow, fd);
	}
}

void handle_host_tcp_data_eof(Context* ctx, TcpFlow* flow, int fd) {
	LOG_D("Handling EOF. host_eof=%d epoll_in_disabled=%d", flow->host_eof,
	    flow->epoll_in_disabled);
	if (!flow->host_eof) {
		flow->host_eof = true;
		if (!flow->epoll_in_disabled) {
			flow->epoll_in_disabled = true;
			if (!tcp_update_host_mask(flow)) {
				PLOG_E("monitor::modFd() failed in eof");
				tcp_rst_and_destroy(ctx, flow);
				return;
			} else {
				LOG_D("monitor::modFd() removed EPOLLIN successfully");
			}
		}
	}
	push_to_guest(ctx, flow);
}

void handle_host_tcp(Context* ctx, TcpFlow* flow, uint32_t events) {
	int fd = flow->header.host_fd;
	flow->header.last_active = time(nullptr);

	LOG_D("handle_host_tcp fd=%d, events=0x%x, state=%d", fd, events, (int)flow->tcp_state);

	if (flow->tcp_state == TcpState::SYN_SENT && (events & EPOLLOUT)) {
		if (flow->inbound) {
			/* Inbound flow already connected, waiting for SYN-ACK from guest */
			/* Avoid immediate EPOLLOUT spin, wait for data */
			if (flow->epoll_out_registered) {
				flow->epoll_out_registered = false;
				if (!tcp_update_host_mask(flow)) {
					PLOG_E("tcp_update_host_mask() failed");
					tcp_rst_and_destroy(ctx, flow);
					return;
				}
			}
		} else {
			handle_host_tcp_connected(ctx, flow, fd);
			return;
		}
	}

	if (events & EPOLLIN) {
		handle_host_tcp_data(ctx, flow, fd);
		/* handle_host_tcp_data may destroy the flow (e.g. RST, error) */
		if (get_tcp_flow_by_fd(ctx, fd) == nullptr) {
			return;
		}
	}

	if ((events & EPOLLOUT) && flow->c_tcp_rx_len > flow->rx_sent_offset) {
		if (flow->tcp_state == TcpState::ESTABLISHED ||
		    flow->tcp_state == TcpState::CLOSE_WAIT) {
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
			if (get_tcp_flow_by_fd(ctx, fd) == nullptr) {
				return;
			}
		}
		if (flow->guest_eof) {
			tcp_destroy_flow(ctx, flow);
			return;
		}
	}
}

static bool handle_inbound_tcp6(Context* ctx, int fd, const nstun_rule_t& rule,
    const struct sockaddr_in6& client6, uint16_t listen_port) {
	/* Loopback->gateway rewrite for IPv6: prevent martian drops in guest */
	uint8_t client_ip6[IPV6_ADDR_LEN];
	memcpy(client_ip6, &client6.sin6_addr, sizeof(client_ip6));
	if (IN6_IS_ADDR_LOOPBACK(&client6.sin6_addr)) {
		memcpy(client_ip6, ctx->host_ip6, sizeof(client_ip6));
	}

	FlowKey6 key6 = {};
	memcpy(key6.saddr6, rule.redirect_ip6, sizeof(key6.saddr6));
	bool has_redirect_ip6 =
	    !IN6_IS_ADDR_UNSPECIFIED(reinterpret_cast<const struct in6_addr*>(rule.redirect_ip6));
	if (!has_redirect_ip6) {
		memcpy(key6.saddr6, ctx->guest_ip6, sizeof(key6.saddr6));
	}
	memcpy(key6.daddr6, client_ip6, sizeof(key6.daddr6));
	key6.sport = rule.redirect_port ? htons(rule.redirect_port) : listen_port;
	key6.dport = client6.sin6_port;

	if (find_v6_tcp_flow(ctx, key6)) {
		LOG_W("IPv6 flow already exists");
		return false;
	}

	TcpFlow* array_flow = alloc_v6_tcp_flow(ctx, key6);
	if (!array_flow) {
		LOG_W("Max flows reached");
		return false;
	}

	array_flow->header.host_fd = fd;
	array_flow->header.is_ipv6 = rule.is_ipv6;
	array_flow->header.last_active = time(nullptr);
	array_flow->inbound = true;
	uint32_t isn = generate_isn();
	array_flow->seq_to_guest = isn;
	array_flow->ack_from_guest = array_flow->seq_to_guest;

	if (!set_tcp_flow_by_fd(ctx, fd, array_flow)) {
		LOG_E("FD %d out of bounds for c_tcp_flows_by_fd", fd);
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}

	LOG_D("Sending SYN to guest (IPv6)");
	if (!tcp_send_packet6(ctx, array_flow, NSTUN_TCP_FLAG_SYN)) {
		LOG_W("Failed to send SYN to guest (IPv6)");
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}
	array_flow->seq_to_guest++;

	LOG_D("Accepted inbound TCP6 %s:%u -> %s:%u (fd=%d)", ip6_to_string(key6.daddr6).c_str(),
	    ntohs(key6.dport), ip6_to_string(key6.saddr6).c_str(), ntohs(key6.sport), fd);

	if (!monitor::addFd(fd, EPOLLIN | EPOLLERR | EPOLLHUP, host_callback, ctx)) {
		PLOG_E("monitor::addFd() for host accept");
		set_tcp_flow_by_fd(ctx, fd, nullptr);
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}
	return true;
}

static bool handle_inbound_tcp4(Context* ctx, int fd, const nstun_rule_t& rule,
    const struct sockaddr_in& client4, uint16_t listen_port) {
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

	TcpFlow* array_flow = find_v4_tcp_flow(ctx, key4);
	if (array_flow) {
		LOG_W("Flow already exists");
		return false;
	}

	array_flow = alloc_v4_tcp_flow(ctx, key4);
	if (!array_flow) {
		LOG_W("Max flows reached");
		return false;
	}

	array_flow->header.host_fd = fd;
	array_flow->header.is_ipv6 = rule.is_ipv6;
	array_flow->header.last_active = time(nullptr);
	array_flow->inbound = true;
	uint32_t isn = generate_isn();
	array_flow->seq_to_guest = isn;
	array_flow->ack_from_guest = array_flow->seq_to_guest;

	if (!set_tcp_flow_by_fd(ctx, fd, array_flow)) {
		LOG_E("FD %d out of bounds for c_tcp_flows_by_fd", fd);
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}

	/* Initiate the flow to the guest by sending SYN */
	LOG_D("Sending SYN to guest");
	if (!tcp_send_packet4(ctx, array_flow, NSTUN_TCP_FLAG_SYN)) {
		LOG_W("Failed to send SYN to guest");
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}
	array_flow->seq_to_guest++;

	LOG_D("Accepted inbound TCP %s:%u -> %s:%u (fd=%d)", ip4_to_string(key4.daddr4).c_str(),
	    ntohs(key4.dport), ip4_to_string(key4.saddr4).c_str(), ntohs(key4.sport), fd);

	if (!monitor::addFd(fd, EPOLLIN | EPOLLERR | EPOLLHUP, host_callback, ctx)) {
		PLOG_E("monitor::addFd() for host accept");
		set_tcp_flow_by_fd(ctx, fd, nullptr);
		array_flow->header.host_fd = -1;
		tcp_destroy_flow(ctx, array_flow);
		return false;
	}
	return true;
}

void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_tcp_accept listen_fd=%d", listen_fd);

	uint16_t listen_port = 0;
	struct sockaddr_storage listen_addr = {};
	socklen_t listen_addrlen = sizeof(listen_addr);
	if (getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&listen_addr),
		&listen_addrlen) == -1) {
		PLOG_E("getsockname(listen_fd) failed");
		return;
	}
	if (rule.is_ipv6) {
		listen_port = reinterpret_cast<struct sockaddr_in6*>(&listen_addr)->sin6_port;
	} else {
		listen_port = reinterpret_cast<struct sockaddr_in*>(&listen_addr)->sin_port;
	}

	if (rule.is_ipv6) {
		if (ctx->num_c_ipv6_tcp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Max IPv6 TCP flows reached, dropping inbound connection");
			return;
		}
	} else {
		if (ctx->num_c_ipv4_tcp_flows >= NSTUN_MAX_FLOWS) {
			LOG_W("Max IPv4 TCP flows reached, dropping inbound connection");
			return;
		}
	}

	int fd = -1;
	int opt = 1;
	bool success = false;

	struct sockaddr_storage client_addr = {};
	socklen_t addrlen = sizeof(client_addr);
	fd = TEMP_FAILURE_RETRY(accept4(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr),
	    &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC));
	if (fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_E("accept4()");
		}
		return;
	}
	LOG_D("Accepted fd=%d", fd);
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
		PLOG_W("setsockopt(TCP_NODELAY)");
	}

	if (rule.is_ipv6) {
		success = handle_inbound_tcp6(ctx, fd, rule,
		    *reinterpret_cast<struct sockaddr_in6*>(&client_addr), listen_port);
	} else {
		success = handle_inbound_tcp4(ctx, fd, rule,
		    *reinterpret_cast<struct sockaddr_in*>(&client_addr), listen_port);
	}

	if (!success) {
		close(fd);
	}
}

void handle_tcp6(Context* ctx, const ip6_hdr* ip, const uint8_t* payload, size_t payload_len) {
	if (payload_len < sizeof(tcp_hdr)) {
		return;
	}
	tcp_hdr tcp;
	memcpy(&tcp, payload, sizeof(tcp));
	uint8_t doff = tcp_doff(&tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > payload_len) {
		return;
	}

	/* Validate TCP checksum */
	pseudo_hdr6 phdr = {};
	phdr.len = htonl(payload_len);
	phdr.next_header = IPPROTO_TCP;
	memcpy(phdr.saddr, ip->saddr, sizeof(phdr.saddr));
	memcpy(phdr.daddr, ip->daddr, sizeof(phdr.daddr));
	uint32_t csum = compute_checksum_part(&phdr, sizeof(phdr), 0);
	csum = compute_checksum_part(payload, payload_len, csum);
	if (finalize_checksum(csum) != 0) {
		LOG_D("Invalid IPv6 TCP checksum, dropping");
		return;
	}

	FlowKey6 key6 = {};
	memcpy(key6.saddr6, ip->saddr, sizeof(key6.saddr6));
	memcpy(key6.daddr6, ip->daddr, sizeof(key6.daddr6));
	key6.sport = tcp.source;
	key6.dport = tcp.dest;

	uint32_t seq = ntohl(tcp.seq);
	uint32_t ack = ntohl(tcp.ack_seq);

	TcpFlow* flow = find_v6_tcp_flow(ctx, key6);

	if (flow) {
		flow->header.last_active = time(nullptr);
	} else {
		if (!(tcp.flags & NSTUN_TCP_FLAG_SYN)) {
			return;
		}
		flow = create_outbound_flow6(ctx, ip, &tcp, key6, seq);
		if (!flow) {
			return;
		}
		return;
	}

	tcp_process_data(ctx, flow, &tcp, payload, payload_len, doff);
}

void handle_host_tcp_event(Context* ctx, TcpFlow* flow, int fd, uint32_t events) {
	if (fd == flow->header.host_fd) {
		handle_host_tcp(ctx, flow, events);
	}
}

void tcp_periodic_check(Context* ctx, TcpFlow* flow, time_t now) {
	bool has_unacked_data = (int32_t)(flow->seq_to_guest - flow->ack_from_guest) > 0;
	bool is_idle = (now - flow->header.last_active >= TCP_TIMEOUT_RTO);
	if (has_unacked_data && is_idle) {
		LOG_D("TCP RTO triggered for flow (fd=%d)", flow->header.host_fd);
		flow->seq_to_guest = flow->ack_from_guest;
		push_to_guest(ctx, flow);
		flow->header.last_active = now;
	}
}

bool is_stale_tcp(const TcpFlow* flow, time_t now) {
	time_t timeout = TCP_TIMEOUT_ESTABLISHED;
	switch (flow->tcp_state) {
	case TcpState::SYN_SENT:
	case TcpState::SOCKS5_INIT:
	case TcpState::SOCKS5_CONNECTING:
	case TcpState::HTTP_CONNECT_WAIT:
		timeout = TCP_TIMEOUT_CONNECTING;
		break;
	case TcpState::TIME_WAIT:
	case TcpState::CLOSING:
		timeout = TCP_TIMEOUT_CLOSING;
		break;
	case TcpState::CLOSE_WAIT:
	case TcpState::FIN_WAIT_1:
	case TcpState::FIN_WAIT_2:
		timeout = TCP_TIMEOUT_FIN;
		break;
	default:
		break;
	}

	return (now - flow->header.last_active) > timeout;
}

} /* namespace nstun */
