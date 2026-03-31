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

#include "logs.h"
#include "macros.h"
#include "socks5.h"
#include "tun.h"
#include "util.h"

namespace nstun {

void handle_host_tcp_connected(Context* ctx, TcpFlow* flow, int fd);

static TcpFlow::ProxyMode proxy_mode_from_action(nstun_action_t action) {
	switch (action) {
	case NSTUN_ACTION_ENCAP_SOCKS5:
		return TcpFlow::ProxyMode::SOCKS5;
	case NSTUN_ACTION_ENCAP_CONNECT:
		return TcpFlow::ProxyMode::HTTP_CONNECT;
	default:
		return TcpFlow::ProxyMode::NONE;
	}
}

static constexpr size_t HTTP_PROXY_RESPONSE_MAX = 8192;

/*
 * Scan for the \r\n\r\n that terminates HTTP headers.
 * Returns the offset one past the final \n, or 0 if not found.
 */
static size_t find_end_of_headers(const std::vector<uint8_t>& buf) {
	for (size_t i = 0; i + 3 < buf.size(); i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
		    buf[i + 3] == '\n') {
			return i + 4;
		}
	}
	return 0;
}

/*
 * Validate an HTTP status line: "HTTP/1.X YZZ..."
 * Accept HTTP/1.0 and HTTP/1.1 with a 2xx status code.
 */
static bool http_status_ok(const std::vector<uint8_t>& buf) {
	/* Minimum: "HTTP/1.0 200" = 12 bytes */
	if (buf.size() < 12) return false;
	if (memcmp(buf.data(), "HTTP/1.", 7) != 0) return false;
	if (buf[7] != '0' && buf[7] != '1') /* minor version */
		return false;
	if (buf[8] != ' ') /* SP separator  */
		return false;
	if (buf[9] != '2') /* 2xx class     */
		return false;
	return true;
}

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

void tcp_send_packet4(Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet4: data length too large (%zu)", len);
		return;
	}

	constexpr uint8_t TCP_OPT_NOP = 1;
	constexpr uint8_t TCP_OPT_MSS = 2;
	constexpr uint8_t TCP_OPT_MSS_LEN = 4;
	constexpr uint8_t TCP_OPT_WSCALE = 3;
	constexpr uint8_t TCP_OPT_WSCALE_LEN = 3;

	size_t opt_len = 0;
	uint8_t options[40];
	if (flags & NSTUN_TCP_FLAG_SYN) {
		/* Add MSS option */
		tcp_opt_mss* mss_opt = reinterpret_cast<tcp_opt_mss*>(&options[opt_len]);
		*mss_opt = {
		    .kind = TCP_OPT_MSS,
		    .len = TCP_OPT_MSS_LEN,
		    .mss = htons(65495),
		};
		opt_len += sizeof(tcp_opt_mss);

		/* Add NOP for 32-bit alignment */
		options[opt_len++] = TCP_OPT_NOP;

		/* Add Window Scale option */
		tcp_opt_wscale* wscale_opt = reinterpret_cast<tcp_opt_wscale*>(&options[opt_len]);
		*wscale_opt = {
		    .kind = TCP_OPT_WSCALE,
		    .len = TCP_OPT_WSCALE_LEN,
		    .shift = 8,
		};
		opt_len += sizeof(tcp_opt_wscale);
	}

	/* Single-threaded network loop: use static buffer for header only */
	static thread_local uint8_t frame_buf[sizeof(ip4_hdr) + sizeof(tcp_hdr) + 40];

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(frame_buf);
	tcp_hdr* r_tcp = reinterpret_cast<tcp_hdr*>(frame_buf + sizeof(ip4_hdr));
	uint8_t* r_opt = frame_buf + sizeof(ip4_hdr) + sizeof(tcp_hdr);

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
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

	constexpr uint8_t TCP_OPT_NOP = 1;
	constexpr uint8_t TCP_OPT_MSS = 2;
	constexpr uint8_t TCP_OPT_MSS_LEN = 4;
	constexpr uint8_t TCP_OPT_WSCALE = 3;
	constexpr uint8_t TCP_OPT_WSCALE_LEN = 3;

	size_t opt_len = 0;
	uint8_t options[40];
	if (flags & NSTUN_TCP_FLAG_SYN) {
		/* Add MSS option */
		tcp_opt_mss* mss_opt = reinterpret_cast<tcp_opt_mss*>(&options[opt_len]);
		*mss_opt = {
		    .kind = TCP_OPT_MSS,
		    .len = TCP_OPT_MSS_LEN,
		    .mss = htons(65495),
		};
		opt_len += sizeof(tcp_opt_mss);

		/* Add NOP for 32-bit alignment */
		options[opt_len++] = TCP_OPT_NOP;

		/* Add Window Scale option */
		tcp_opt_wscale* wscale_opt = reinterpret_cast<tcp_opt_wscale*>(&options[opt_len]);
		*wscale_opt = {
		    .kind = TCP_OPT_WSCALE,
		    .len = TCP_OPT_WSCALE_LEN,
		    .shift = 8,
		};
		opt_len += sizeof(tcp_opt_wscale);
	}

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
		close(flow->host_fd);
	}
	if (flow->is_ipv6) {
		ctx->ipv6_tcp_flows_by_key.erase(flow->key6);
	} else {
		ctx->ipv4_tcp_flows_by_key.erase(flow->key4);
	}
	if (flow->host_fd != -1) {
		ctx->tcp_flows_by_host_fd.erase(flow->host_fd);
	}
	delete flow;
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

void handle_tcp4(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(tcp_hdr)) {
		return;
	}

	const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(payload);
	uint8_t doff = tcp_doff(tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > len) {
		return;
	}

	FlowKey4 key4 = {ip->saddr, ip->daddr, tcp->source, tcp->dest};

	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	auto it = ctx->ipv4_tcp_flows_by_key.find(key4);
	TcpFlow* flow = nullptr;

	if (it != ctx->ipv4_tcp_flows_by_key.end()) {
		flow = it->second;
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
			char dst_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
			LOG_D("TCP connect to %s:%u dropped by policy", dst_str, dest_port);
			return;
		} else if (rule.action == NSTUN_ACTION_REJECT) {
			char dst_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
			LOG_D("TCP connect to %s:%u rejected by policy", dst_str, dest_port);
			tcp_send_rst4(ctx, key4, 0, seq + 1);
			return;
		}

		/* Open socket to dest */
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket(AF_INET, SOCK_STREAM)");
			return;
		}

		int opt = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

		bool success = false;
		defer {
			if (!success) {
				close(fd);
			}
		};

		struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);

		if (rule.redirect_ip4 && rule.redirect_port) {
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			char redir_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &dest_addr.sin_addr, redir_str, sizeof(redir_str));
			LOG_D("Redirecting TCP flow guest %u to host %s:%u via policy (fd=%d)",
			    guest_port, redir_str, rule.redirect_port, fd);
		} else {
			uint32_t real_dest_ip = key4.daddr4;
			if (real_dest_ip == ctx->host_ip4) {
				real_dest_ip = htonl(INADDR_LOOPBACK);
			} else if (IN_LOOPBACK(ntohl(real_dest_ip))) {
				/* SSRF Protection: Guest forged a 127.x.x.x packet over TUN */
				char ssrf_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &real_dest_ip, ssrf_str, sizeof(ssrf_str));
				LOG_W("TCP SSRF blocked: Guest forged loopback destination %s",
				    ssrf_str);
				tcp_send_rst4(ctx, key4, 0, seq + 1);
				return;
			}
			dest_addr.sin_addr.s_addr = real_dest_ip;
			dest_addr.sin_port = tcp->dest;
			char flow_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &dest_addr.sin_addr, flow_str, sizeof(flow_str));
			LOG_D("New TCP flow guest %u -> host %s:%u (fd=%d)", guest_port, flow_str,
			    dest_port, fd);
		}

		struct epoll_event ev = {
		    .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			PLOG_E("epoll_ctl(EPOLL_CTL_ADD)");
			return;
		}

		/* Network setup successful! Create flow. */
		success = true;

		flow = new TcpFlow{.host_fd = fd,
		    .is_ipv6 = false,
		    .key4 = key4,
		    .state = TcpState::SYN_SENT,
		    .proxy_mode = proxy_mode_from_action(rule.action),
		    .host_eof = false,
		    .guest_eof = false,
		    .fin_sent = false,
		    .syn_acked = false,
		    .fin_acked = false,
		    .seq_to_guest = (uint32_t)util::rnd64(), /* random ISN */
		    .ack_from_guest = 0,		     /* set below */
		    .seq_from_guest = seq + 1,
		    .ack_to_guest = seq + 1,
		    .guest_window = 0,
		    .tx_buffer = {},
		    .tx_acked_offset = 0,
		    .socks5_rx_buffer = {},
		    .rx_buffer = {},
		    .rx_sent_offset = 0,
		    .epoll_out_registered = true,
		    .epoll_in_disabled = false,
		    .inbound = false,
		    .last_active = time(NULL)};
		flow->ack_from_guest = flow->seq_to_guest;

		ctx->ipv4_tcp_flows_by_key[key4] = flow;
		ctx->tcp_flows_by_host_fd[fd] = flow;

		int ret = connect(fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		if (ret == 0) {
			/* Immediate connect (e.g. localhost) */
			handle_host_tcp_connected(ctx, flow, fd);
		} else if (errno == EINPROGRESS) {
			/* Wait for EPOLLOUT */
		} else {
			PLOG_E("connect() failed");
			tcp_destroy_flow(ctx, flow);
		}

		return;
	}

	if (flow->inbound && flow->state == TcpState::SYN_SENT &&
	    (tcp->flags & NSTUN_TCP_FLAG_SYN) && (tcp->flags & NSTUN_TCP_FLAG_ACK)) {
		flow->state = TcpState::ESTABLISHED;
		flow->ack_from_guest = ack;
		flow->seq_from_guest = seq + 1; /* account for SYN */
		flow->ack_to_guest = flow->seq_from_guest;
		flow->syn_acked = true;

		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);

		if (!flow->tx_buffer.empty()) {
			push_to_guest(ctx, flow);
		}

		if (flow->epoll_in_disabled) {
			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLERR | EPOLLHUP |
				      (flow->epoll_out_registered ? EPOLLOUT : (EPOLL_EVENTS)0),
			    .data = {.fd = flow->host_fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, flow->host_fd, &ev);
			flow->epoll_in_disabled = false;
		}
		return;
	}

	if (tcp->flags & NSTUN_TCP_FLAG_RST) {
		LOG_D("Received RST from guest for port %u", ntohs(key4.sport));
		tcp_destroy_flow(ctx, flow);
		return;
	}

	if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::FIN_WAIT_1 ||
	    flow->state == TcpState::FIN_WAIT_2 || flow->state == TcpState::SYN_SENT ||
	    flow->state == TcpState::CLOSE_WAIT) {
		const uint8_t* data = payload + doff;
		size_t data_len = len - doff;

		if (data_len > 0) {
			int32_t diff = seq - flow->ack_to_guest;
			int32_t end_diff = (seq + data_len) - flow->ack_to_guest;

			if (diff <= 0 && end_diff > 0) {
				/* Handle in-order or overlapping data */
				uint32_t overlap = flow->ack_to_guest - seq;
				const uint8_t* new_data = data + overlap;
				size_t new_data_len = data_len - overlap;

				if (flow->rx_buffer.size() + new_data_len > (1024 * 1024 * 8)) {
					LOG_D("TCP rx_buffer reached 8MB limit for guest %u "
					      "(DoS protection), dropping",
					    ntohs(key4.sport));
					return;
				}

				flow->rx_buffer.insert(
				    flow->rx_buffer.end(), new_data, new_data + new_data_len);
				flow->seq_from_guest += new_data_len;
				flow->ack_to_guest = flow->seq_from_guest;

				if (flush_to_host(ctx, flow)) {
					return; /* Flow was destroyed */
				}
			} else if (diff > 0) {
				/* Out of order future data, drop and ACK what we have */
				tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
			} else {
				/* Completely old data, just ACK */
				tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
			}
		}

		/* Process ACKs from guest */
		if (tcp->flags & NSTUN_TCP_FLAG_ACK) {
			if (flow->state == TcpState::SYN_SENT) {
				/* Guest ACKed our SYN-ACK */
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

					flow->tx_acked_offset += acked_bytes;

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
						128 * 1024)) {
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
			/* Duplicate ACK -> Fast Retransmit */
			flow->seq_to_guest = flow->ack_from_guest;
			push_to_guest(ctx, flow);
		}

		if (tcp->flags & NSTUN_TCP_FLAG_FIN) {
			LOG_D("Received FIN from guest");
			flow->seq_from_guest++; /* FIN counts as 1 byte */
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
	case TcpFlow::ProxyMode::NONE:
		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;
		return;

	case TcpFlow::ProxyMode::HTTP_CONNECT: {
		flow->state = TcpState::HTTP_CONNECT_INIT;
		char connect_str[512];
		int len;
		if (flow->is_ipv6) {
			char dst_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, flow->key6.daddr6, dst_str, sizeof(dst_str));
			len = snprintf(connect_str, sizeof(connect_str),
			    "CONNECT [%s]:%u HTTP/1.1\r\nHost: [%s]:%u\r\n\r\n", dst_str,
			    ntohs(flow->key6.dport), dst_str, ntohs(flow->key6.dport));
		} else {
			char dst_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &flow->key4.daddr4, dst_str, sizeof(dst_str));
			len = snprintf(connect_str, sizeof(connect_str),
			    "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n", dst_str,
			    ntohs(flow->key4.dport), dst_str, ntohs(flow->key4.dport));
		}
		if (len < 0 || (size_t)len >= sizeof(connect_str)) {
			LOG_E("HTTP CONNECT request truncated");
			tcp_destroy_flow(ctx, flow);
			return;
		}
		if (send(fd, connect_str, len, MSG_NOSIGNAL) != len) {
			PLOG_E("send() HTTP CONNECT request");
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}

	case TcpFlow::ProxyMode::SOCKS5:
		flow->state = TcpState::SOCKS5_INIT;
		socks5_greeting greeting = {
		    .ver = SOCKS5_VERSION,
		    .num_auth = 1,
		    .auth = {SOCKS5_AUTH_NONE},
		};
		if (send(fd, &greeting, sizeof(greeting), MSG_NOSIGNAL) !=
		    (ssize_t)sizeof(greeting)) {
			PLOG_E("send() SOCKS5 greeting");
			tcp_destroy_flow(ctx, flow);
			return;
		}
		return;
	}
}

void handle_host_tcp_data(Context* ctx, TcpFlow* flow, int fd) {
	switch (flow->state) {
	case TcpState::SOCKS5_INIT: {
		socks5_auth_reply buf;
		ssize_t recv_len =
		    recv(fd, &buf, sizeof(buf) - flow->socks5_rx_buffer.size(), MSG_DONTWAIT);
		if (recv_len == 0) goto rst;
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			goto err;
		}

		flow->socks5_rx_buffer.insert(flow->socks5_rx_buffer.end(),
		    reinterpret_cast<uint8_t*>(&buf), reinterpret_cast<uint8_t*>(&buf) + recv_len);
		if (flow->socks5_rx_buffer.size() < 2) return;

		socks5_auth_reply* reply =
		    reinterpret_cast<socks5_auth_reply*>(flow->socks5_rx_buffer.data());
		if (reply->ver != SOCKS5_VERSION || reply->method != SOCKS5_AUTH_NONE) {
			goto rst;
		}

		flow->socks5_rx_buffer.clear();
		flow->state = TcpState::SOCKS5_CONNECTING;
		if (flow->is_ipv6) {
			socks5_req6 req = {
			    .ver = SOCKS5_VERSION,
			    .cmd = SOCKS5_CMD_CONNECT,
			    .rsv = 0x00,
			    .atyp = SOCKS5_ATYP_IPV6,
			    .dst_ip6 = {0},
			    .dst_port = flow->key6.dport,
			};
			memcpy(req.dst_ip6, flow->key6.daddr6, sizeof(req.dst_ip6));
			if (send(flow->host_fd, &req, sizeof(req), MSG_NOSIGNAL) !=
			    (ssize_t)sizeof(req)) {
				goto rst;
			}
		} else {
			socks5_req req = {
			    .ver = SOCKS5_VERSION,
			    .cmd = SOCKS5_CMD_CONNECT,
			    .rsv = 0x00,
			    .atyp = SOCKS5_ATYP_IPV4,
			    .dst_ip4 = flow->key4.daddr4,
			    .dst_port = flow->key4.dport,
			};
			if (send(flow->host_fd, &req, sizeof(req), MSG_NOSIGNAL) !=
			    (ssize_t)sizeof(req)) {
				goto rst;
			}
		}
		return;
	}

	case TcpState::SOCKS5_CONNECTING: {
		socks5_max_buf buf;
		size_t to_read = sizeof(buf);
		/* Let's be smart about expected length */
		size_t current_len = flow->socks5_rx_buffer.size();
		if (current_len >= 4) {
			socks5_req* reply =
			    reinterpret_cast<socks5_req*>(flow->socks5_rx_buffer.data());
			uint8_t atyp = reply->atyp;
			size_t expected_len = 0;
			if (atyp == SOCKS5_ATYP_IPV4) {
				expected_len = 10;
			} else if (atyp == SOCKS5_ATYP_IPV6) {
				expected_len = 22;
			} else if (atyp == SOCKS5_ATYP_DOMAIN) {
				if (current_len >= 5) {
					socks5_req_domain* dreq =
					    reinterpret_cast<socks5_req_domain*>(
						flow->socks5_rx_buffer.data());
					expected_len = 5 + dreq->domain_len + 2;
				}
			}
			if (expected_len > 0) {
				to_read = expected_len - current_len;
			}
		}

		if (to_read > 0) {
			ssize_t recv_len = recv(fd, &buf, to_read, MSG_DONTWAIT);
			if (recv_len == 0) goto rst;
			if (recv_len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) return;
				goto err;
			}
			flow->socks5_rx_buffer.insert(
			    flow->socks5_rx_buffer.end(), buf.data, buf.data + recv_len);
		}

		current_len = flow->socks5_rx_buffer.size();
		if (current_len < 4) return;

		socks5_req* reply = reinterpret_cast<socks5_req*>(flow->socks5_rx_buffer.data());
		if (reply->ver != SOCKS5_VERSION || reply->cmd != SOCKS5_REP_SUCCESS) {
			goto rst;
		}

		uint8_t atyp = reply->atyp;
		size_t expected_len = 0;
		if (atyp == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (atyp == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (atyp == SOCKS5_ATYP_DOMAIN) {
			if (current_len < 5) return;
			socks5_req_domain* dreq =
			    reinterpret_cast<socks5_req_domain*>(flow->socks5_rx_buffer.data());
			expected_len = 5 + dreq->domain_len + 2;
		} else {
			goto rst; /* Unknown ATYP */
		}

		if (current_len < expected_len) return; /* Wait for full response */

		/* We have the full response, transition to established */
		flow->socks5_rx_buffer.clear();
		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;
		return;
	}

	case TcpState::HTTP_CONNECT_INIT: {
		uint8_t buf[HTTP_PROXY_RESPONSE_MAX];
		ssize_t recv_len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (recv_len == 0) goto rst;
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			goto err;
		}

		auto& rx = flow->socks5_rx_buffer;
		rx.insert(rx.end(), buf, buf + recv_len);

		size_t end_of_headers = find_end_of_headers(rx);
		if (end_of_headers == 0) {
			if (rx.size() > HTTP_PROXY_RESPONSE_MAX) {
				LOG_E("HTTP proxy response too long");
				goto rst;
			}
			return; /* Wait for more data */
		}

		if (!http_status_ok(rx)) {
			LOG_E("HTTP CONNECT failed: %.*s",
			    (int)std::min(end_of_headers, (size_t)64), rx.data());
			goto rst;
		}

		/* Anything after the headers is tunnelled payload — forward it */
		if (rx.size() > end_of_headers) {
			flow->tx_buffer.insert(flow->tx_buffer.end(), rx.data() + end_of_headers,
			    rx.data() + rx.size());
		}
		rx.clear();

		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;

		if (!flow->tx_buffer.empty()) {
			push_to_guest(ctx, flow);
		}
		return;
	}

	case TcpState::ESTABLISHED:
	case TcpState::FIN_WAIT_1:
	case TcpState::FIN_WAIT_2:
	case TcpState::CLOSE_WAIT:
	case TcpState::SYN_SENT:
		if (flow->state == TcpState::SYN_SENT && !flow->inbound) {
			return; /* Should not happen, SYN_SENT handled elsewhere */
		}
		{
			uint8_t buf[65536];
			ssize_t recv_len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (recv_len == 0) goto eof;
			if (recv_len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) return;
				goto err;
			}

			flow->tx_buffer.insert(flow->tx_buffer.end(), buf, buf + recv_len);

			if (flow->state != TcpState::SYN_SENT) {
				push_to_guest(ctx, flow);
			}

			if (flow->tx_buffer.size() - flow->tx_acked_offset > 256 * 1024) {
				if (!flow->epoll_in_disabled) {
					struct epoll_event ev = {
					    .events =
						EPOLLERR | EPOLLHUP |
						(flow->epoll_out_registered ? (uint32_t)EPOLLOUT
									    : 0),
					    .data = {.fd = fd}};
					epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
					flow->epoll_in_disabled = true;
				}
			}
			return;
		}

	default:
		return;
	}

	return;

eof:
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
	return;

err:
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return;
	}
	/* fallthrough to rst */
rst:
	tcp_rst_and_destroy(ctx, flow);
	return;
}

void handle_host_tcp(Context* ctx, int fd, uint32_t events) {
	auto it = ctx->tcp_flows_by_host_fd.find(fd);
	if (it == ctx->tcp_flows_by_host_fd.end()) {
		return;
	}
	TcpFlow* flow = it->second;
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
		if (ctx->tcp_flows_by_host_fd.find(fd) == ctx->tcp_flows_by_host_fd.end()) {
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

	if ((events & EPOLLERR) || (events & EPOLLHUP)) {
		tcp_rst_and_destroy(ctx, flow);
	}
}

void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_tcp_accept listen_fd=%d", listen_fd);
	if (ctx->tcp_flows_by_host_fd.size() >= NSTUN_MAX_FLOWS) {
		LOG_W("Max flows reached");
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

	TcpFlow* flow = new TcpFlow();
	bool flow_success = false;
	defer {
		if (!flow_success) tcp_destroy_flow(ctx, flow);
	};

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
	flow->proxy_mode = TcpFlow::ProxyMode::NONE; /* Proxies not supported for inbound */
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
		uint8_t client_ip6[16];
		memcpy(client_ip6, &client6->sin6_addr, sizeof(client_ip6));
		if (IN6_IS_ADDR_LOOPBACK(&client6->sin6_addr)) {
			memcpy(client_ip6, ctx->host_ip6, sizeof(client_ip6));
		}

		FlowKey6 key6 = {};
		memcpy(key6.saddr6, rule.redirect_ip6, 16);
		bool has_redirect_ip6 = false;
		for (int j = 0; j < 16; j++) {
			if (rule.redirect_ip6[j] != 0) {
				has_redirect_ip6 = true;
				break;
			}
		}
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
		ctx->ipv6_tcp_flows_by_key[key6] = flow;
		ctx->tcp_flows_by_host_fd[fd] = flow;

		LOG_D("Sending SYN to guest (IPv6)");
		tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_SYN);
		flow->seq_to_guest++;

		char src_str[INET6_ADDRSTRLEN];
		char dst_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, key6.daddr6, src_str, sizeof(src_str));
		inet_ntop(AF_INET6, key6.saddr6, dst_str, sizeof(dst_str));
		LOG_D("Accepted inbound TCP6 %s:%u -> %s:%u (fd=%d)", src_str, ntohs(key6.dport),
		    dst_str, ntohs(key6.sport), fd);
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
		ctx->ipv4_tcp_flows_by_key[key4] = flow;
		ctx->tcp_flows_by_host_fd[fd] = flow;

		/* Initiate the flow to the guest by sending SYN */
		LOG_D("Sending SYN to guest");
		tcp_send_packet4(ctx, flow, NSTUN_TCP_FLAG_SYN);
		flow->seq_to_guest++;

		char src_str[INET_ADDRSTRLEN];
		char dst_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &key4.daddr4, src_str, sizeof(src_str));
		inet_ntop(AF_INET, &key4.saddr4, dst_str, sizeof(dst_str));
		LOG_D("Accepted inbound TCP %s:%u -> %s:%u (fd=%d)", src_str, ntohs(key4.dport),
		    dst_str, ntohs(key4.sport), fd);
	}

	flow_success = true;
}

void handle_tcp6(Context* ctx, const ip6_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(tcp_hdr)) return;
	const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(payload);
	uint8_t doff = tcp_doff(tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > len) return;

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
		flow = it->second;
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
		int fd = socket(
		    use_proxy ? AF_INET : AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket() IPv6 TCP outbound");
			return;
		}

		int opt = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

		bool success = false;
		defer {
			if (!success) close(fd);
		};

		if (use_proxy) {
			struct sockaddr_in dest_addr = INIT_SOCKADDR_IN(AF_INET);
			dest_addr.sin_addr.s_addr = rule.redirect_ip4;
			dest_addr.sin_port = htons(rule.redirect_port);
			LOG_D("Connecting IPv6 TCP flow guest %u to IPv4 proxy %u (fd=%d)",
			    guest_port, rule.redirect_port, fd);

			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
				PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for IPv6 TCP proxy");
				return;
			}

			success = true;

			flow = new TcpFlow{.host_fd = fd,
			    .is_ipv6 = true,
			    .key6 = key6,
			    .state = TcpState::SYN_SENT,
			    .proxy_mode = proxy_mode_from_action(rule.action),
			    .host_eof = false,
			    .guest_eof = false,
			    .fin_sent = false,
			    .syn_acked = false,
			    .fin_acked = false,
			    .seq_to_guest = (uint32_t)util::rnd64(),
			    .ack_from_guest = 0,
			    .seq_from_guest = seq + 1,
			    .ack_to_guest = seq + 1,
			    .guest_window = 0,
			    .tx_buffer = {},
			    .tx_acked_offset = 0,
			    .socks5_rx_buffer = {},
			    .rx_buffer = {},
			    .rx_sent_offset = 0,
			    .epoll_out_registered = true,
			    .epoll_in_disabled = false,
			    .inbound = false,
			    .last_active = time(NULL)};
			flow->ack_from_guest = flow->seq_to_guest;

			ctx->ipv6_tcp_flows_by_key[key6] = flow;
			ctx->tcp_flows_by_host_fd[fd] = flow;

			int ret = connect(fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			if (ret == 0) {
				handle_host_tcp_connected(ctx, flow, fd);
			} else if (errno == EINPROGRESS) {
				/* Wait for EPOLLOUT */
			} else {
				PLOG_E("connect() IPv6 proxy failed");
				tcp_destroy_flow(ctx, flow);
			}
			return;
		}

		struct sockaddr_in6 dest_addr = INIT_SOCKADDR_IN6(AF_INET6);

		if (rule.has_redirect_ip6 && rule.redirect_port) {
			memcpy(
			    &dest_addr.sin6_addr, rule.redirect_ip6, sizeof(dest_addr.sin6_addr));
			dest_addr.sin6_port = htons(rule.redirect_port);
			char redir_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &dest_addr.sin6_addr, redir_str, sizeof(redir_str));
			LOG_D("Redirecting IPv6 TCP flow guest %u to host %s:%u via policy (fd=%d)",
			    guest_port, redir_str, rule.redirect_port, fd);
		} else {
			/* Gateway→loopback rewrite: traffic to host_ip6 goes to ::1 */
			if (memcmp(key6.daddr6, ctx->host_ip6, 16) == 0) {
				struct in6_addr lo6 = IN6ADDR_LOOPBACK_INIT;
				memcpy(&dest_addr.sin6_addr, &lo6, sizeof(dest_addr.sin6_addr));
			} else if (IN6_IS_ADDR_LOOPBACK((const struct in6_addr*)key6.daddr6) ||
				   IN6_IS_ADDR_V4MAPPED((const struct in6_addr*)key6.daddr6)) {
				char ssrf_str[INET6_ADDRSTRLEN];
				inet_ntop(
				    AF_INET6, &dest_addr.sin6_addr, ssrf_str, sizeof(ssrf_str));
				LOG_W("TCP SSRF blocked: Guest forged loopback destination %s",
				    ssrf_str);
				tcp_send_rst6(ctx, key6, 0, seq + 1);
				return;
			} else {
				memcpy(
				    &dest_addr.sin6_addr, key6.daddr6, sizeof(dest_addr.sin6_addr));
			}
			dest_addr.sin6_port = tcp->dest;
			char flow_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &dest_addr.sin6_addr, flow_str, sizeof(flow_str));
			LOG_D("New IPv6 TCP flow guest %u -> host %s:%u (fd=%d)", guest_port,
			    flow_str, dest_port, fd);
		}
		struct epoll_event ev = {
		    .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for IPv6 TCP");
			return;
		}

		success = true;

		flow = new TcpFlow{.host_fd = fd,
		    .is_ipv6 = true,
		    .key6 = key6,
		    .state = TcpState::SYN_SENT,
		    .proxy_mode = TcpFlow::ProxyMode::NONE,
		    .host_eof = false,
		    .guest_eof = false,
		    .fin_sent = false,
		    .syn_acked = false,
		    .fin_acked = false,
		    .seq_to_guest = (uint32_t)util::rnd64(),
		    .ack_from_guest = 0,
		    .seq_from_guest = seq + 1,
		    .ack_to_guest = seq + 1,
		    .guest_window = 0,
		    .tx_buffer = {},
		    .tx_acked_offset = 0,
		    .socks5_rx_buffer = {},
		    .rx_buffer = {},
		    .rx_sent_offset = 0,
		    .epoll_out_registered = true,
		    .epoll_in_disabled = false,
		    .inbound = false,
		    .last_active = time(NULL)};
		flow->ack_from_guest = flow->seq_to_guest;

		ctx->ipv6_tcp_flows_by_key[key6] = flow;
		ctx->tcp_flows_by_host_fd[fd] = flow;

		int ret = connect(fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		if (ret == 0) {
			flow->state = TcpState::ESTABLISHED;
			tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
			flow->seq_to_guest++;
		} else if (errno == EINPROGRESS) {
			/* Wait for EPOLLOUT */
		} else {
			PLOG_E("connect() IPv6 failed");
			tcp_destroy_flow(ctx, flow);
		}

		return;
	}

	if (flow->inbound && flow->state == TcpState::SYN_SENT &&
	    (tcp->flags & NSTUN_TCP_FLAG_SYN) && (tcp->flags & NSTUN_TCP_FLAG_ACK)) {
		flow->state = TcpState::ESTABLISHED;
		flow->ack_from_guest = ack;
		flow->seq_from_guest = seq + 1;
		flow->ack_to_guest = flow->seq_from_guest;
		flow->syn_acked = true;

		tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_ACK);

		if (!flow->tx_buffer.empty()) {
			push_to_guest(ctx, flow);
		}

		if (flow->epoll_in_disabled) {
			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLERR | EPOLLHUP |
				      (flow->epoll_out_registered ? EPOLLOUT : (EPOLL_EVENTS)0),
			    .data = {.fd = flow->host_fd}};
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, flow->host_fd, &ev);
			flow->epoll_in_disabled = false;
		}
		return;
	}

	if (tcp->flags & NSTUN_TCP_FLAG_RST) {
		LOG_D("Received RST from guest for port %u", ntohs(key6.sport));
		tcp_destroy_flow(ctx, flow);
		return;
	}

	if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::FIN_WAIT_1 ||
	    flow->state == TcpState::FIN_WAIT_2 || flow->state == TcpState::SYN_SENT ||
	    flow->state == TcpState::CLOSE_WAIT) {
		const uint8_t* data = payload + doff;
		size_t data_len = len - doff;

		if (data_len > 0) {
			int32_t diff = seq - flow->ack_to_guest;
			int32_t end_diff = (seq + data_len) - flow->ack_to_guest;

			if (diff <= 0 && end_diff > 0) {
				uint32_t overlap = flow->ack_to_guest - seq;
				const uint8_t* new_data = data + overlap;
				size_t new_data_len = data_len - overlap;

				if (flow->rx_buffer.size() + new_data_len > (1024 * 1024 * 8)) {
					LOG_D("IPv6 TCP rx_buffer reached 8MB limit for guest %u "
					      "(DoS protection), dropping",
					    ntohs(key6.sport));
					return;
				}

				flow->rx_buffer.insert(
				    flow->rx_buffer.end(), new_data, new_data + new_data_len);
				flow->seq_from_guest += new_data_len;
				flow->ack_to_guest = flow->seq_from_guest;

				if (flush_to_host(ctx, flow)) {
					return;
				}
			} else if (diff > 0) {
				tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_ACK);
			} else {
				tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_ACK);
			}
		}

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

					flow->tx_acked_offset += acked_bytes;

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
						128 * 1024)) {
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
				} else if (data_len == 0 &&
					   !(tcp->flags & (NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_SYN |
							      NSTUN_TCP_FLAG_RST))) {
					flow->seq_to_guest = flow->ack_from_guest;
					push_to_guest(ctx, flow);
				}
			}

			if (flow->state == TcpState::FIN_WAIT_1 && ack == flow->seq_to_guest) {
				flow->state = TcpState::FIN_WAIT_2;
			}
		}

		if (tcp->flags & NSTUN_TCP_FLAG_FIN) {
			LOG_D("Received FIN from guest");
			flow->seq_from_guest++;
			flow->ack_to_guest = flow->seq_from_guest;

			tcp_send_packet6(ctx, flow, NSTUN_TCP_FLAG_ACK);

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

} /* namespace nstun */
