#include "tcp.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logs.h"
#include "macros.h"
#include "socks5.h"

namespace nstun {

void tcp_send_packet(Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data, size_t len) {
	size_t frame_len = sizeof(ip4_hdr) + sizeof(tcp_hdr) + len;
	uint8_t* frame_buf = new uint8_t[frame_len]();

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(frame_buf);
	tcp_hdr* r_tcp = reinterpret_cast<tcp_hdr*>(frame_buf + sizeof(ip4_hdr));
	uint8_t* r_data = frame_buf + sizeof(ip4_hdr) + sizeof(tcp_hdr);

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(sizeof(ip4_hdr) + sizeof(tcp_hdr) + len);
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
	tcp_set_doff(r_tcp, sizeof(tcp_hdr) / 4);
	r_tcp->flags = flags;
	r_tcp->window = htons(65535); /* Large window */
	r_tcp->check = 0;
	r_tcp->urg_ptr = 0;

	if (data && len > 0) {
		memcpy(r_data, data, len);
	}

	uint8_t pbuf[12];
	memcpy(pbuf, &flow->key.daddr, 4);
	memcpy(pbuf + 4, &flow->key.saddr, 4);
	pbuf[8] = 0;
	pbuf[9] = NSTUN_IPPROTO_TCP;
	uint16_t tlen = htons(sizeof(tcp_hdr) + len);
	memcpy(pbuf + 10, &tlen, 2);

	uint32_t psum = 0;
	const uint16_t* p = reinterpret_cast<const uint16_t*>(pbuf);
	for (size_t i = 0; i < 6; ++i) psum += p[i];

	uint32_t tsum = 0;
	p = reinterpret_cast<const uint16_t*>(r_tcp);
	for (size_t i = 0; i < 10; ++i) tsum += p[i];

	uint32_t sum = psum + tsum;
	if (len > 0 && data) {
		const uint16_t* d = reinterpret_cast<const uint16_t*>(data);
		size_t dlen = len;
		while (dlen > 1) {
			sum += *d++;
			dlen -= 2;
		}
		if (dlen == 1) {
			sum += *reinterpret_cast<const uint8_t*>(d);
		}
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	r_tcp->check = static_cast<uint16_t>(~sum);

	send_to_guest(ctx, frame_buf, frame_len);
	delete[] frame_buf;
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
				tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_FIN | NSTUN_TCP_FLAG_ACK);
				flow->seq_to_guest++;
				flow->fin_sent = true;
			}
		}
		return; /* Everything is in flight */
	}

	size_t to_send = available - in_flight;
	if (to_send > 1400) to_send = 1400; /* MTU chunking */

	const uint8_t* data = flow->tx_buffer.data() + flow->tx_acked_offset + in_flight;
	tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK | NSTUN_TCP_FLAG_PSH, data, to_send);
	flow->seq_to_guest += to_send;
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

		/* If it's not a SYN, we drop or send RST */
		if (!(tcp->flags & NSTUN_TCP_FLAG_SYN)) {
			return;
		}

		/* SYN: evaluate policies */
		uint32_t redirect_ip = 0;
		uint16_t redirect_port = 0;
		uint16_t guest_port = ntohs(tcp->source);
		uint16_t dest_port = ntohs(tcp->dest);

		nstun_action_t act = evaluate_rules(ctx, NSTUN_PROTO_TCP, ip->saddr, ip->daddr,
		    guest_port, dest_port, &redirect_ip, &redirect_port);

		if (act == NSTUN_ACTION_DROP) {
			char dst_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
			LOG_D("TCP flow %u -> %s:%u dropped by policy", guest_port, dst_str,
			    dest_port);
			return;
		} else if (act == NSTUN_ACTION_REJECT) {
			char rej_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ip->daddr, rej_str, sizeof(rej_str));
			LOG_D("TCP flow %u -> %s:%u rejected by policy", guest_port, rej_str,
			    dest_port);
			TcpFlow dummy_flow = {};
			dummy_flow.key = key;
			dummy_flow.seq_to_guest = 0;
			dummy_flow.ack_to_guest = seq + 1;
			tcp_send_packet(ctx, &dummy_flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
			return;
		}

		/* Open socket to dest */
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd == -1) {
			PLOG_E("socket(AF_INET, SOCK_STREAM)");
			return;
		}

		bool success = false;
		defer {
			if (!success) {
				close(fd);
			}
		};

		struct sockaddr_in dest_addr = {};
		dest_addr.sin_family = AF_INET;

		if (redirect_ip && redirect_port) {
			dest_addr.sin_addr.s_addr = redirect_ip;
			dest_addr.sin_port = htons(redirect_port);
			char redir_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &dest_addr.sin_addr, redir_str, sizeof(redir_str));
			LOG_D("Redirecting TCP flow guest %u to host %s:%u via policy (fd=%d)",
			    guest_port, redir_str, redirect_port, fd);
		} else {
			uint32_t real_dest_ip = key.daddr;
			if (real_dest_ip == ctx->host_ip) {
				real_dest_ip = htonl(INADDR_LOOPBACK);
			} else if ((ntohl(real_dest_ip) & 0xFF000000) == 0x7F000000) {
				/* SSRF Protection: Guest forged a 127.x.x.x packet over TUN */
				char ssrf_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &real_dest_ip, ssrf_str, sizeof(ssrf_str));
				LOG_W("TCP SSRF blocked: Guest forged loopback destination %s",
				    ssrf_str);
				TcpFlow dummy_flow = {};
				dummy_flow.key = key;
				dummy_flow.seq_to_guest = 0;
				dummy_flow.ack_to_guest = seq + 1;
				tcp_send_packet(
				    ctx, &dummy_flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
				return;
			}
			dest_addr.sin_addr.s_addr = real_dest_ip;
			dest_addr.sin_port = tcp->dest;
			char flow_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &dest_addr.sin_addr, flow_str, sizeof(flow_str));
			LOG_D("New TCP flow guest %u -> host %s:%u (fd=%d)", guest_port,
			    flow_str, dest_port, fd);
		}

		struct epoll_event ev = {};
		ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
		ev.data.fd = fd;
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			PLOG_E("epoll_ctl(EPOLL_CTL_ADD)");
			return;
		}

		/* Network setup successful! Create flow. */
		success = true;

		flow = new TcpFlow();
		flow->key = key;
		flow->state = TcpState::SYN_SENT;
		flow->epoll_out_registered = true;
		flow->epoll_in_disabled = false;
		flow->host_eof = false;
		flow->guest_eof = false;
		flow->fin_sent = false;
		flow->syn_acked = false;
		flow->fin_acked = false;
		flow->use_socks5 = (act == NSTUN_ACTION_ENCAP_SOCKS5);
		flow->last_active = time(NULL);

		flow->seq_from_guest = seq + 1;
		flow->ack_to_guest = flow->seq_from_guest;
		flow->seq_to_guest = (uint32_t)random(); /* random ISN */
		flow->ack_from_guest = flow->seq_to_guest;
		flow->tx_acked_offset = 0;

		flow->host_fd = fd;
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

				ssize_t written =
				    send(flow->host_fd, new_data, new_data_len, MSG_NOSIGNAL);
				if (written > 0) {
					flow->seq_from_guest += written;
					flow->ack_to_guest = flow->seq_from_guest;
					tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK);
				} else if (written < 0 &&
					   (errno == EAGAIN || errno == EWOULDBLOCK)) {
					/* Drop, guest will retransmit */
				} else {
					tcp_send_packet(
					    ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
					tcp_destroy_flow(ctx, flow);
					return;
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
						struct epoll_event ev = {};
						ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
						ev.data.fd = flow->host_fd;
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

	struct epoll_event ev = {};
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = fd;
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
		uint8_t peek_buf[2];
		ssize_t peek_len = recv(fd, peek_buf, sizeof(peek_buf), MSG_PEEK);
		if (peek_len == 0) goto eof;
		if (peek_len < 0) goto err;
		if (peek_len < 2) return;

		recv(fd, peek_buf, 2, 0);
		if (peek_buf[0] != SOCKS5_VERSION || peek_buf[1] != SOCKS5_AUTH_NONE) goto rst;

		flow->state = TcpState::SOCKS5_CONNECTING;
		uint8_t req[10] = {SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4};
		memcpy(&req[4], &flow->key.daddr, 4);
		memcpy(&req[8], &flow->key.dport, 2);
		send(flow->host_fd, req, 10, MSG_NOSIGNAL);
		return;
	}

	if (flow->state == TcpState::SOCKS5_CONNECTING) {
		uint8_t peek_buf[512]; /* Handle arbitrary length responses natively and safely */
		ssize_t peek_len = recv(fd, peek_buf, sizeof(peek_buf), MSG_PEEK);
		if (peek_len == 0) goto eof;
		if (peek_len < 0) goto err;
		if (peek_len < 4) return;

		if (peek_buf[0] != SOCKS5_VERSION || peek_buf[1] != SOCKS5_REP_SUCCESS) goto rst;

		size_t expected_len = 0;
		if (peek_buf[3] == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (peek_buf[3] == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (peek_buf[3] == SOCKS5_ATYP_DOMAIN) {
			if (peek_len < 5) return;
			expected_len = 5 + peek_buf[4] + 2;
		} else {
			goto rst; /* Unknown ATYP */
		}

		if ((size_t)peek_len < expected_len) return; /* Wait for full response */

		/* Consume the exact response length cleanly */
		recv(fd, peek_buf, expected_len, 0);

		flow->state = TcpState::ESTABLISHED;
		tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK);
		flow->seq_to_guest++;
		return;
	}

	if (flow->state == TcpState::ESTABLISHED || flow->state == TcpState::FIN_WAIT_1 ||
	    flow->state == TcpState::FIN_WAIT_2 || flow->state == TcpState::CLOSE_WAIT) {
		uint8_t buf[65536];
		ssize_t recv_len = recv(fd, buf, sizeof(buf), 0);
		LOG_D("recv_len=%zd errno=%d", recv_len, errno);
		if (recv_len == 0) goto eof;
		if (recv_len < 0) goto err;

		flow->tx_buffer.insert(flow->tx_buffer.end(), buf, buf + recv_len);
		push_to_guest(ctx, flow);

		if (flow->tx_buffer.size() - flow->tx_acked_offset > 256 * 1024) {
			struct epoll_event ev = {};
			ev.events = EPOLLERR | EPOLLHUP;
			ev.data.fd = fd;
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
			flow->epoll_in_disabled = true;
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
			struct epoll_event ev = {};
			ev.events = EPOLLERR | EPOLLHUP;
			ev.data.fd = fd;
			if (flow->epoll_out_registered) ev.events |= EPOLLOUT;
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
		handle_host_tcp_connected(ctx, flow, fd);
		return;
	}

	if (events & EPOLLIN) {
		handle_host_tcp_data(ctx, flow, fd);
	} else if ((events & EPOLLERR) || (events & EPOLLHUP)) {
		if (flow->state != TcpState::SYN_SENT) {
			tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_RST | NSTUN_TCP_FLAG_ACK);
		}
		tcp_destroy_flow(ctx, flow);
	}
}

} /* namespace nstun */
