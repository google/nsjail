#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "logs.h"
#include "macros.h"
#include "socks5.h"

namespace nstun {

void udp_destroy_flow(Context* ctx, UdpFlow* flow) {
	if (flow->host_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		close(flow->host_fd);
	}
	if (flow->tcp_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->tcp_fd, nullptr);
		close(flow->tcp_fd);
	}
	ctx->udp_flows_by_key.erase(flow->key);
	if (flow->host_fd != -1) {
		ctx->udp_flows_by_host_fd.erase(flow->host_fd);
	}
	if (flow->tcp_fd != -1) {
		ctx->udp_flows_by_tcp_fd.erase(flow->tcp_fd);
	}
	delete flow;
}

void handle_host_udp_control(Context* ctx, int fd, uint32_t events) {
	auto it = ctx->udp_flows_by_tcp_fd.find(fd);
	if (it == ctx->udp_flows_by_tcp_fd.end()) {
		return;
	}
	UdpFlow* flow = it->second;
	flow->last_active = time(NULL);

	if (flow->state == UdpSocks5State::TCP_CONNECTING) {
		if (events & EPOLLOUT) {
			int err = 0;
			socklen_t errlen = sizeof(err);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
			if (err != 0) {
				udp_destroy_flow(ctx, flow);
				return;
			}
			struct epoll_event ev = {};
			ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
			ev.data.fd = fd;
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);

			flow->state = UdpSocks5State::SOCKS5_GREETING;
			uint8_t greeting[] = {
			    SOCKS5_VERSION, 1 /* number of auth methods */, SOCKS5_AUTH_NONE};
			send(fd, greeting, sizeof(greeting), MSG_NOSIGNAL);
		} else {
			udp_destroy_flow(ctx, flow);
		}
		return;
	}

	if (flow->state == UdpSocks5State::SOCKS5_GREETING) {
		uint8_t buf[2];
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK);
		if (n <= 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		if (n < 2) return;
		recv(fd, buf, 2, 0);
		if (buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_AUTH_NONE) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		flow->state = UdpSocks5State::SOCKS5_ASSOCIATE;
		/* UDP ASSOCIATE */
		uint8_t req[10] = {SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00, SOCKS5_ATYP_IPV4,
		    0, 0, 0, 0, 0, 0};
		send(fd, req, 10, MSG_NOSIGNAL);
		return;
	}

	if (flow->state == UdpSocks5State::SOCKS5_ASSOCIATE) {
		uint8_t buf[512]; /* Handle arbitrary length responses safely */
		ssize_t peek_len = recv(fd, buf, sizeof(buf), MSG_PEEK);
		if (peek_len <= 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		if (peek_len < 4) return;
		if (buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_REP_SUCCESS) {
			udp_destroy_flow(ctx, flow);
			return;
		}

		size_t expected_len = 0;
		if (buf[3] == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (buf[3] == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (buf[3] == SOCKS5_ATYP_DOMAIN) {
			if (peek_len < 5) return;
			expected_len = 5 + buf[4] + 2;
		} else {
			udp_destroy_flow(ctx, flow);
			return;
		}

		if ((size_t)peek_len < expected_len) return;
		recv(fd, buf, expected_len, 0);

		if (buf[3] == SOCKS5_ATYP_IPV4) {
			memcpy(&flow->bnd_ip, &buf[4], 4);
			memcpy(&flow->bnd_port, &buf[8], 2);
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
		struct sockaddr_in bind_addr = {};
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_addr.s_addr = INADDR_ANY;
		bind_addr.sin_port = 0;
		if (bind(udp_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
			close(udp_fd);
			udp_destroy_flow(ctx, flow);
			return;
		}
		struct epoll_event ev = {};
		ev.events = EPOLLIN;
		ev.data.fd = udp_fd;
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev) == -1) {
			close(udp_fd);
			udp_destroy_flow(ctx, flow);
			return;
		}
		flow->host_fd = udp_fd;
		ctx->udp_flows_by_host_fd[udp_fd] = flow;
		flow->state = UdpSocks5State::ESTABLISHED;

		for (const auto& pkt : flow->tx_queue) {
			struct sockaddr_in dest_addr = {};
			dest_addr.sin_family = AF_INET;
			dest_addr.sin_addr.s_addr = flow->bnd_ip;
			dest_addr.sin_port = flow->bnd_port;

			std::vector<uint8_t> s5_pkt(10 + pkt.size());
			s5_pkt[0] = 0x00;
			s5_pkt[1] = 0x00;
			s5_pkt[2] = 0x00;
			s5_pkt[3] = SOCKS5_ATYP_IPV4;
			memcpy(&s5_pkt[4], &flow->orig_dest_ip, 4);
			uint16_t ndport = htons(flow->orig_dest_port);
			memcpy(&s5_pkt[8], &ndport, 2);
			memcpy(&s5_pkt[10], pkt.data(), pkt.size());
			sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), 0,
			    (struct sockaddr*)&dest_addr, sizeof(dest_addr));
		}
		flow->tx_queue.clear();
		return;
	}

	if (events & (EPOLLERR | EPOLLHUP) || (events & EPOLLIN)) {
		uint8_t buf[1];
		if (recv(fd, buf, 1, MSG_PEEK) <= 0) {
			udp_destroy_flow(ctx, flow);
		}
	}
}

void handle_udp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len) {
	if (len < sizeof(udp_hdr)) {
		return;
	}

	const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(payload);
	uint16_t guest_port = ntohs(udp->source);
	uint16_t dest_port = ntohs(udp->dest);

	FlowKey key = {ip->saddr, ip->daddr, udp->source, udp->dest};

	uint32_t redirect_ip = 0;
	uint16_t redirect_port = 0;
	nstun_action_t act = evaluate_rules(ctx, NSTUN_PROTO_UDP, ip->saddr, ip->daddr, guest_port,
	    dest_port, &redirect_ip, &redirect_port);

	if (act == NSTUN_ACTION_DROP) {
		char dst_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
		LOG_D("UDP flow %u -> %s:%u dropped by policy", guest_port, dst_str, dest_port);
		return;
	} else if (act == NSTUN_ACTION_REJECT) {
		char rej_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip->daddr, rej_str, sizeof(rej_str));
		LOG_D("UDP flow %u -> %s:%u rejected by policy", guest_port, rej_str, dest_port);
		send_icmp_error(ctx, ip, 3, 3); /* Port unreachable */
		return;
	}

	/* Find or create flow */
	UdpFlow* flow = nullptr;
	auto it = ctx->udp_flows_by_key.find(key);
	if (it != ctx->udp_flows_by_key.end()) {
		flow = it->second;
		flow->last_active = time(NULL);
	} else {
		if (ctx->udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W(
			    "Maximum number of UDP flows (%zu) reached, dropping", NSTUN_MAX_FLOWS);
			return;
		}

		flow = new UdpFlow();
		flow->host_fd = -1;
		flow->tcp_fd = -1;
		flow->key = key;
		flow->last_active = time(NULL);
		flow->is_redirected = (redirect_ip != 0 || redirect_port != 0);
		flow->orig_dest_ip = ip->daddr;
		flow->orig_dest_port = dest_port;
		flow->use_socks5 = (act == NSTUN_ACTION_ENCAP_SOCKS5);

		if (flow->use_socks5) {
			int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (tcp_fd == -1) {
				delete flow;
				return;
			}
			bool success = false;
			defer {
				if (!success) close(tcp_fd);
			};
			struct epoll_event ev = {};
			ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
			ev.data.fd = tcp_fd;
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, tcp_fd, &ev) == -1) {
				delete flow;
				return;
			}
			struct sockaddr_in dest_addr = {};
			dest_addr.sin_family = AF_INET;
			dest_addr.sin_addr.s_addr = redirect_ip;
			dest_addr.sin_port = htons(redirect_port);
			connect(tcp_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
			success = true;
			flow->tcp_fd = tcp_fd;
			flow->state = UdpSocks5State::TCP_CONNECTING;
			ctx->udp_flows_by_key[key] = flow;
			ctx->udp_flows_by_tcp_fd[tcp_fd] = flow;
			LOG_D("Created UDP SOCKS5 flow for guest port %u -> tcp fd %d%s",
			    guest_port, tcp_fd, flow->is_redirected ? " [redirected]" : "");
		} else {
			int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (fd == -1) {
				PLOG_E("socket(AF_INET, SOCK_DGRAM) for UDP flow failed");
				delete flow;
				return;
			}
			bool success = false;
			defer {
				if (!success) close(fd);
			};
			struct sockaddr_in bind_addr = {};
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_addr.s_addr = INADDR_ANY;
			bind_addr.sin_port = 0; /* Let OS choose */
			if (bind(fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
				PLOG_E("bind() UDP host socket failed");
				delete flow;
				return;
			}
			struct epoll_event ev = {};
			ev.events = EPOLLIN;
			ev.data.fd = fd;
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
				PLOG_E("epoll_ctl(EPOLL_CTL_ADD) for UDP host socket failed");
				delete flow;
				return;
			}
			success = true;
			flow->host_fd = fd;
			flow->state = UdpSocks5State::ESTABLISHED;
			ctx->udp_flows_by_key[key] = flow;
			ctx->udp_flows_by_host_fd[fd] = flow;
			LOG_D("Created UDP flow for guest port %u -> fd %d%s", guest_port, fd,
			    flow->is_redirected ? " [redirected]" : "");
		}
	}

	const uint8_t* data = payload + sizeof(udp_hdr);
	size_t data_len = len - sizeof(udp_hdr);

	if (flow->use_socks5 && flow->state != UdpSocks5State::ESTABLISHED) {
		std::vector<uint8_t> pkt(data, data + data_len);
		flow->tx_queue.push_back(pkt);
		if (flow->tx_queue.size() > 50) {
			/* Do not buffer indefinitely */
			flow->tx_queue.erase(flow->tx_queue.begin());
		}
		return;
	}

	struct sockaddr_in dest_addr = {};
	dest_addr.sin_family = AF_INET;

	if (flow->use_socks5) {
		dest_addr.sin_addr.s_addr = flow->bnd_ip;
		dest_addr.sin_port = flow->bnd_port;

		std::vector<uint8_t> s5_pkt(10 + data_len);
		s5_pkt[0] = 0x00;
		s5_pkt[1] = 0x00;
		s5_pkt[2] = 0x00;
		s5_pkt[3] = SOCKS5_ATYP_IPV4;
		memcpy(&s5_pkt[4], &flow->orig_dest_ip, 4);
		uint16_t ndport = htons(flow->orig_dest_port);
		memcpy(&s5_pkt[8], &ndport, 2);
		memcpy(&s5_pkt[10], data, data_len);

		sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), 0, (struct sockaddr*)&dest_addr,
		    sizeof(dest_addr));
	} else {
		if (redirect_ip && redirect_port) {
			dest_addr.sin_addr.s_addr = redirect_ip;
			dest_addr.sin_port = htons(redirect_port);
		} else {
			uint32_t real_dest_ip = ip->daddr;
			if (real_dest_ip == ctx->host_ip) {
				real_dest_ip = htonl(INADDR_LOOPBACK);
			} else if ((ntohl(real_dest_ip) & 0xFF000000) == 0x7F000000) {
				LOG_W("UDP SSRF blocked: Guest forged loopback destination");
				send_icmp_error(ctx, ip, 3, 3); /* Port unreachable */
				return;
			}
			dest_addr.sin_addr.s_addr = real_dest_ip;
			dest_addr.sin_port = htons(dest_port);
		}
		sendto(flow->host_fd, data, data_len, 0, (struct sockaddr*)&dest_addr,
		    sizeof(dest_addr));
	}
}

void handle_host_udp(Context* ctx, int fd) {
	auto it = ctx->udp_flows_by_host_fd.find(fd);
	if (it == ctx->udp_flows_by_host_fd.end()) {
		return; /* Should not happen */
	}
	UdpFlow* flow = it->second;
	flow->last_active = time(NULL);

	uint8_t buf[65536];
	struct sockaddr_in src_addr = {};
	socklen_t addrlen = sizeof(src_addr);

	ssize_t recv_len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &addrlen);
	if (recv_len <= 0) {
		if (recv_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}
		PLOG_E("recvfrom(fd=%d) failed", fd);
		udp_destroy_flow(ctx, flow);
		return;
	}

	uint8_t* data_ptr = buf;
	size_t data_len = recv_len;

	if (flow->use_socks5) {
		if (data_len < 10) return;
		if (buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00) return;

		size_t header_len = 0;
		if (buf[3] == SOCKS5_ATYP_IPV4) {
			header_len = 10;
		} else if (buf[3] == SOCKS5_ATYP_IPV6) {
			header_len = 22;
		} else if (buf[3] == SOCKS5_ATYP_DOMAIN) {
			if (data_len < 5) return;
			header_len = 5 + buf[4] + 2;
		} else {
			return;
		}

		if (data_len < header_len) return;

		data_ptr = buf + header_len;
		data_len -= header_len;
	}

	/* Construct UDP + IP frame to send to guest */
	size_t frame_len = sizeof(ip4_hdr) + sizeof(udp_hdr) + data_len;
	uint8_t* frame_buf = new uint8_t[frame_len]();
	defer {
		delete[] frame_buf;
	};

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(frame_buf);
	udp_hdr* r_udp = reinterpret_cast<udp_hdr*>(frame_buf + sizeof(ip4_hdr));
	uint8_t* r_data = frame_buf + sizeof(ip4_hdr) + sizeof(udp_hdr);

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(sizeof(ip4_hdr) + sizeof(udp_hdr) + data_len);
	r_ip->id = 0; /* Or some counter */
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = NSTUN_IPPROTO_UDP;
	if (flow->is_redirected || flow->use_socks5) {
		r_ip->saddr = flow->orig_dest_ip;
		r_udp->source = htons(flow->orig_dest_port);
	} else {
		r_ip->saddr = src_addr.sin_addr.s_addr; /* The actual source of the packet */
		r_udp->source = src_addr.sin_port;
	}
	r_ip->daddr = flow->key.saddr;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* UDP */
	r_udp->dest = flow->key.sport;
	r_udp->len = htons(sizeof(udp_hdr) + data_len);
	r_udp->check = 0; /* Disable checksum for IPv4 */

	/* Copy data */
	memcpy(r_data, data_ptr, data_len);

	uint8_t pbuf[12];
	memcpy(pbuf, &r_ip->saddr, 4);
	memcpy(pbuf + 4, &r_ip->daddr, 4);
	pbuf[8] = 0;
	pbuf[9] = NSTUN_IPPROTO_UDP;
	uint16_t tlen = htons(sizeof(udp_hdr) + data_len);
	memcpy(pbuf + 10, &tlen, 2);

	uint32_t psum = 0;
	const uint16_t* p = reinterpret_cast<const uint16_t*>(pbuf);
	for (size_t i = 0; i < 6; ++i) psum += p[i];

	uint32_t usum = 0;
	p = reinterpret_cast<const uint16_t*>(r_udp);
	for (size_t i = 0; i < 4; ++i) usum += p[i];

	uint32_t sum = psum + usum;
	if (data_len > 0) {
		const uint16_t* d = reinterpret_cast<const uint16_t*>(data_ptr);
		size_t dlen = data_len;
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
	r_udp->check = static_cast<uint16_t>(~sum);
	if (r_udp->check == 0) {
		r_udp->check = 0xFFFF; /* UDP checksum 0 means no checksum, send 0xFFFF instead */
	}

	send_to_guest(ctx, frame_buf, frame_len);
}

} /* namespace nstun */
