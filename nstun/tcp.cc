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

static void tcp_send_rst(Context* ctx, const FlowKey& key, uint32_t seq, uint32_t ack) {
	TcpFlow dummy_flow = {};
	dummy_flow.key = key;
	dummy_flow.seq_to_guest = seq;
	dummy_flow.ack_to_guest = ack;
	tcp_send_packet(ctx, &dummy_flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
}

void tcp_send_packet(Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	if (len > NSTUN_MTU) {
		LOG_W("tcp_send_packet: data length too large (%zu)", len);
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
		/* Add MSS option (Kind=2, Length=4, MSS=65495) */
		options[opt_len++] = TCP_OPT_MSS;
		options[opt_len++] = TCP_OPT_MSS_LEN;
		uint16_t mss = htons(65495);
		memcpy(&options[opt_len], &mss, 2);
		opt_len += 2;

		/* Add NOP for 32-bit alignment */
		options[opt_len++] = TCP_OPT_NOP;

		/* Add Window Scale option (Kind=3, Length=3, Shift=8) */
		options[opt_len++] = TCP_OPT_WSCALE;
		options[opt_len++] = TCP_OPT_WSCALE_LEN;
		options[opt_len++] = 8;
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
	r_ip->protocol = NSTUN_IPPROTO_TCP;
	r_ip->saddr = flow->key.daddr;
	r_ip->daddr = flow->key.saddr;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* TCP */
	r_tcp->source = flow->key.dport;
	r_tcp->dest = flow->key.sport;
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

	uint8_t pbuf[12];
	memcpy(pbuf, &flow->key.daddr, 4);
	memcpy(pbuf + 4, &flow->key.saddr, 4);
	pbuf[8] = 0;
	pbuf[9] = NSTUN_IPPROTO_TCP;
	uint16_t tlen = htons(sizeof(tcp_hdr) + opt_len + len);
	memcpy(pbuf + 10, &tlen, 2);

	uint32_t sum = compute_checksum_part(pbuf, sizeof(pbuf), 0);
	sum = compute_checksum_part(r_tcp, sizeof(tcp_hdr) + opt_len, sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}
	r_tcp->check = finalize_checksum(sum);

	send_to_guest_v(ctx, frame_buf, sizeof(ip4_hdr) + sizeof(tcp_hdr) + opt_len, data, len);
}

void tcp_destroy_flow(Context* ctx, TcpFlow* flow) {
	if (flow->host_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		close(flow->host_fd);
	}
	ctx->tcp_flows_by_key.erase(flow->key);
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
	constexpr size_t max_seg = NSTUN_MTU - sizeof(ip4_hdr) - sizeof(tcp_hdr);

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
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK | NSTUN_TCP_FLAG_PSH, data, to_send);
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
		tcp_send_rst(ctx, flow->key, flow->seq_to_guest, flow->ack_to_guest);
		tcp_destroy_flow(ctx, flow);
		return true;
	}
}

void handle_tcp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(tcp_hdr)) {
		return;
	}

	const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(payload);
	uint8_t doff = tcp_doff(tcp) * 4;
	if (doff < sizeof(tcp_hdr) || doff > len) {
		return;
	}

	FlowKey key = {ip->saddr, ip->daddr, tcp->source, tcp->dest};

	uint32_t seq = ntohl(tcp->seq);
	uint32_t ack = ntohl(tcp->ack_seq);

	auto it = ctx->tcp_flows_by_key.find(key);
	TcpFlow* flow = nullptr;

	if (it != ctx->tcp_flows_by_key.end()) {
		flow = it->second;
		flow->last_active = time(NULL);
	} else {
		if (ctx->tcp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
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

		RuleResult rule = evaluate_rules(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_TCP,
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
			tcp_send_rst(ctx, key, 0, seq + 1);
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

		if (rule.redirect_ip && rule.redirect_port) {
			dest_addr.sin_addr.s_addr = rule.redirect_ip;
			dest_addr.sin_port = htons(rule.redirect_port);
			char redir_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &dest_addr.sin_addr, redir_str, sizeof(redir_str));
			LOG_D("Redirecting TCP flow guest %u to host %s:%u via policy (fd=%d)",
			    guest_port, redir_str, rule.redirect_port, fd);
		} else {
			uint32_t real_dest_ip = key.daddr;
			if (real_dest_ip == ctx->host_ip) {
				real_dest_ip = htonl(INADDR_LOOPBACK);
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
		    .key = key,
		    .state = TcpState::SYN_SENT,
		    .use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5),
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

		ctx->tcp_flows_by_key[key] = flow;
		ctx->tcp_flows_by_host_fd[fd] = flow;

		int ret = connect(fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		if (ret == 0) {
			/* Immediate connect (e.g. localhost) */
			flow->state = TcpState::ESTABLISHED;
			tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
			flow->seq_to_guest++; /* SYN counts as 1 byte */
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
		LOG_D("Received RST from guest for port %u", ntohs(key.sport));
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
					char guest_str[INET_ADDRSTRLEN];
					inet_ntop(
					    AF_INET, &ip->saddr, guest_str, sizeof(guest_str));
					LOG_D("TCP rx_buffer reached 8MB limit for guest %s:%u "
					      "(DoS protection), dropping",
					    guest_str, ntohs(key.sport));
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
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
		tcp_destroy_flow(ctx, flow);
		return;
	}

	struct epoll_event ev = {.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
	flow->epoll_out_registered = false;

	if (!flow->use_socks5) {
		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;
		return;
	}

	flow->state = TcpState::SOCKS5_INIT;
	uint8_t greeting[] = {SOCKS5_VERSION, 1 /* number of auth methods */, SOCKS5_AUTH_NONE};
	send(fd, greeting, sizeof(greeting), MSG_NOSIGNAL);
}

void handle_host_tcp_data(Context* ctx, TcpFlow* flow, int fd) {
	if (flow->state == TcpState::SOCKS5_INIT) {
		uint8_t buf[2];
		ssize_t recv_len = recv(fd, buf, 2 - flow->socks5_rx_buffer.size(), 0);
		if (recv_len == 0) goto eof;
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			goto err;
		}

		flow->socks5_rx_buffer.insert(flow->socks5_rx_buffer.end(), buf, buf + recv_len);
		if (flow->socks5_rx_buffer.size() < 2) return;

		if (flow->socks5_rx_buffer[0] != SOCKS5_VERSION ||
		    flow->socks5_rx_buffer[1] != SOCKS5_AUTH_NONE) {
			goto rst;
		}

		flow->socks5_rx_buffer.clear();
		flow->state = TcpState::SOCKS5_CONNECTING;
		socks5_req req = {};
		req.ver = SOCKS5_VERSION;
		req.cmd = SOCKS5_CMD_CONNECT;
		req.rsv = 0x00;
		req.atyp = SOCKS5_ATYP_IPV4;
		req.dst_ip = flow->key.daddr;
		req.dst_port = flow->key.dport;
		send(flow->host_fd, &req, sizeof(req), MSG_NOSIGNAL);
		return;
	}

	if (flow->state == TcpState::SOCKS5_CONNECTING) {
		uint8_t buf[512];
		size_t to_read = sizeof(buf);
		/* Let's be smart about expected length */
		size_t current_len = flow->socks5_rx_buffer.size();
		if (current_len >= 4) {
			uint8_t atyp = flow->socks5_rx_buffer[3];
			size_t expected_len = 0;
			if (atyp == SOCKS5_ATYP_IPV4) {
				expected_len = 10;
			} else if (atyp == SOCKS5_ATYP_IPV6) {
				expected_len = 22;
			} else if (atyp == SOCKS5_ATYP_DOMAIN) {
				if (current_len >= 5) {
					expected_len = 5 + flow->socks5_rx_buffer[4] + 2;
				}
			}
			if (expected_len > 0) {
				to_read = expected_len - current_len;
			}
		}

		if (to_read > 0) {
			ssize_t recv_len = recv(fd, buf, to_read, 0);
			if (recv_len == 0) goto eof;
			if (recv_len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) return;
				goto err;
			}
			flow->socks5_rx_buffer.insert(
			    flow->socks5_rx_buffer.end(), buf, buf + recv_len);
		}

		current_len = flow->socks5_rx_buffer.size();
		if (current_len < 4) return;

		if (flow->socks5_rx_buffer[0] != SOCKS5_VERSION ||
		    flow->socks5_rx_buffer[1] != SOCKS5_REP_SUCCESS) {
			goto rst;
		}

		uint8_t atyp = flow->socks5_rx_buffer[3];
		size_t expected_len = 0;
		if (atyp == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (atyp == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (atyp == SOCKS5_ATYP_DOMAIN) {
			if (current_len < 5) return;
			expected_len = 5 + flow->socks5_rx_buffer[4] + 2;
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

	if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::FIN_WAIT_1 ||
	    flow->state == TcpState::FIN_WAIT_2 || flow->state == TcpState::CLOSE_WAIT ||
	    (flow->inbound && flow->state == TcpState::SYN_SENT)) {
		uint8_t buf[65536];
		ssize_t recv_len = recv(fd, buf, sizeof(buf), 0);
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
				    .events = EPOLLERR | EPOLLHUP |
					      (flow->epoll_out_registered ? (uint32_t)EPOLLOUT : 0),
				    .data = {.fd = fd}};
				epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
				flow->epoll_in_disabled = true;
			}
		}
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
	if (errno != EAGAIN && errno != EWOULDBLOCK) {
	rst:
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
		tcp_destroy_flow(ctx, flow);
	}
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
		if (flow->state != TcpState::SYN_SENT && flow->rx_buffer.empty()) {
			tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
		}
		tcp_destroy_flow(ctx, flow);
	}
}

void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_tcp_accept listen_fd=%d", listen_fd);
	if (ctx->tcp_flows_by_host_fd.size() >= NSTUN_MAX_FLOWS) {
		LOG_W("Max flows reached");
		return;
	}

	struct sockaddr_in client_addr = INIT_SOCKADDR_IN(AF_INET);
	socklen_t addrlen = sizeof(client_addr);
	int fd = accept4(
	    listen_fd, (struct sockaddr*)&client_addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_E("accept4()");
		}
		return;
	}

	LOG_D("Accepted fd=%d", fd);

	int opt = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	struct sockaddr_in server_addr = INIT_SOCKADDR_IN(AF_INET);
	socklen_t servlen = sizeof(server_addr);
	getsockname(fd, (struct sockaddr*)&server_addr, &servlen);

	FlowKey key = {};

	/* Setup reverse flow details */
	key.saddr = rule.redirect_ip ? rule.redirect_ip : ctx->guest_ip;
	key.sport = rule.redirect_port ? htons(rule.redirect_port) : server_addr.sin_port;

	uint32_t client_ip = client_addr.sin_addr.s_addr;
	if (client_ip == htonl(INADDR_LOOPBACK)) {
		client_ip = ctx->host_ip; /* Prevent martian drops in guest */
	}

	key.daddr = client_ip;
	key.dport = client_addr.sin_port;

	if (ctx->tcp_flows_by_key.find(key) != ctx->tcp_flows_by_key.end()) {
		LOG_W("Flow already exists");
		close(fd);
		return;
	}

	TcpFlow* flow = new TcpFlow();
	flow->host_fd = fd;
	flow->key = key;

	struct epoll_event ev = {.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for host accept");
		tcp_destroy_flow(ctx, flow);
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
	flow->use_socks5 = false; /* SOCKS5 is not supported for inbound yet */
	flow->last_active = time(NULL);
	flow->inbound = true;

	flow->seq_from_guest = 0;
	flow->ack_to_guest = 0;
	flow->seq_to_guest = (uint32_t)util::rnd64();
	flow->ack_from_guest = flow->seq_to_guest;
	flow->tx_acked_offset = 0;

	ctx->tcp_flows_by_key[key] = flow;
	ctx->tcp_flows_by_host_fd[fd] = flow;

	/* Initiate the flow to the guest by sending SYN */
	LOG_D("Sending SYN to guest");
	tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN);
	flow->seq_to_guest++;

	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &key.daddr, src_str, sizeof(src_str));
	inet_ntop(AF_INET, &key.saddr, dst_str, sizeof(dst_str));
	LOG_D("Accepted inbound TCP %s:%u -> %s:%u (fd=%d)", src_str, ntohs(key.dport), dst_str,
	    ntohs(key.sport), fd);
}

} /* namespace nstun */
