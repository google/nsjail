#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core.h"
#include "icmp.h"
#include "logs.h"
#include "macros.h"
#include "socks5.h"
#include "tun.h"

namespace nstun {

void udp_destroy_flow(Context* ctx, UdpFlow* flow) {
	if (flow->host_fd != -1 && !flow->host_fd_is_listener) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->host_fd, nullptr);
		close(flow->host_fd);
	}
	if (flow->tcp_fd != -1) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, flow->tcp_fd, nullptr);
		close(flow->tcp_fd);
	}
	ctx->udp_flows_by_key.erase(flow->key);
	if (flow->host_fd != -1 && !flow->host_fd_is_listener) {
		ctx->udp_flows_by_host_fd.erase(flow->host_fd);
	}
	if (flow->tcp_fd != -1) {
		ctx->udp_flows_by_tcp_fd.erase(flow->tcp_fd);
	}
	delete flow;
}

static void udp_send_packet(Context* ctx, uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t dport, const uint8_t* data, size_t len) {
	static thread_local uint8_t header_buf[sizeof(ip4_hdr) + sizeof(udp_hdr)];

	ip4_hdr* r_ip = reinterpret_cast<ip4_hdr*>(header_buf);
	udp_hdr* r_udp = reinterpret_cast<udp_hdr*>(header_buf + sizeof(ip4_hdr));

	/* IPv4 */
	r_ip->ihl_version = (4 << 4) | (sizeof(ip4_hdr) / 4);
	r_ip->tos = 0;
	r_ip->tot_len = htons(sizeof(ip4_hdr) + sizeof(udp_hdr) + len);
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = NSTUN_IPPROTO_UDP;
	r_ip->saddr = saddr;
	r_ip->daddr = daddr;
	r_ip->check = 0;
	r_ip->check = compute_checksum(r_ip, sizeof(ip4_hdr));

	/* UDP */
	r_udp->source = sport;
	r_udp->dest = dport;
	r_udp->len = htons(sizeof(udp_hdr) + len);
	r_udp->check = 0;

	uint8_t pbuf[12];
	memcpy(pbuf, &r_ip->saddr, 4);
	memcpy(pbuf + 4, &r_ip->daddr, 4);
	pbuf[8] = 0;
	pbuf[9] = NSTUN_IPPROTO_UDP;
	uint16_t tlen = htons(sizeof(udp_hdr) + len);
	memcpy(pbuf + 10, &tlen, 2);

	uint32_t sum = compute_checksum_part(pbuf, sizeof(pbuf), 0);
	sum = compute_checksum_part(r_udp, sizeof(udp_hdr), sum);
	if (data && len > 0) {
		sum = compute_checksum_part(data, len, sum);
	}

	r_udp->check = finalize_checksum(sum);
	if (r_udp->check == 0) {
		r_udp->check = 0xFFFF;
	}

	send_to_guest_v(ctx, header_buf, sizeof(header_buf), data, len);
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
			struct epoll_event ev = {
			    .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fd}};
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
		socks5_req req = {};
		req.ver = SOCKS5_VERSION;
		req.cmd = SOCKS5_CMD_UDP_ASSOCIATE;
		req.rsv = 0x00;
		req.atyp = SOCKS5_ATYP_IPV4;
		req.dst_ip = 0;
		req.dst_port = 0;
		send(fd, &req, sizeof(req), MSG_NOSIGNAL);
		return;
	}

	if (flow->state == UdpSocks5State::SOCKS5_ASSOCIATE) {
		socks5_req req = {};
		ssize_t n = recv(fd, &req, sizeof(req), MSG_PEEK);
		if (n <= 0) {
			udp_destroy_flow(ctx, flow);
			return;
		}
		if (n < 4) return;
		if (req.ver != SOCKS5_VERSION || req.cmd != SOCKS5_REP_SUCCESS) {
			udp_destroy_flow(ctx, flow);
			return;
		}

		size_t expected_len = 0;
		if (req.atyp == SOCKS5_ATYP_IPV4) {
			expected_len = 10;
		} else if (req.atyp == SOCKS5_ATYP_IPV6) {
			expected_len = 22;
		} else if (req.atyp == SOCKS5_ATYP_DOMAIN) {
			uint8_t buf[512];
			n = recv(fd, buf, sizeof(buf), MSG_PEEK);
			if (n < 5) return;
			expected_len = 5 + buf[4] + 2;
		} else {
			udp_destroy_flow(ctx, flow);
			return;
		}

		if ((size_t)n < expected_len) return;

		uint8_t buf[512];
		recv(fd, buf, expected_len, 0);

		if (req.atyp == SOCKS5_ATYP_IPV4) {
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
		struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = udp_fd}};
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

			std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr) + pkt.size());
			socks5_udp_hdr* hdr = reinterpret_cast<socks5_udp_hdr*>(s5_pkt.data());
			hdr->rsv = 0;
			hdr->frag = 0;
			hdr->atyp = SOCKS5_ATYP_IPV4;
			hdr->dst_ip = flow->orig_dest_ip;
			hdr->dst_port = htons(flow->orig_dest_port);
			memcpy(s5_pkt.data() + sizeof(socks5_udp_hdr), pkt.data(), pkt.size());
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

	RuleResult rule = evaluate_rules(ctx, NSTUN_DIR_GUEST_TO_HOST, NSTUN_PROTO_UDP, ip->saddr,
	    ip->daddr, guest_port, dest_port);

	if (rule.action == NSTUN_ACTION_DROP) {
		char dst_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
		LOG_D("UDP flow %u -> %s:%u dropped by policy", guest_port, dst_str, dest_port);
		return;
	} else if (rule.action == NSTUN_ACTION_REJECT) {
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
		flow->is_redirected = (rule.redirect_ip != 0 || rule.redirect_port != 0);
		flow->orig_dest_ip = ip->daddr;
		flow->orig_dest_port = dest_port;
		flow->use_socks5 = (rule.action == NSTUN_ACTION_ENCAP_SOCKS5);

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
			struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			    .data = {.fd = tcp_fd}};
			if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, tcp_fd, &ev) == -1) {
				delete flow;
				return;
			}
			struct sockaddr_in dest_addr = {};
			dest_addr.sin_family = AF_INET;
			dest_addr.sin_addr.s_addr = rule.redirect_ip;
			dest_addr.sin_port = htons(rule.redirect_port);
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
			struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = fd}};
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

		std::vector<uint8_t> s5_pkt(sizeof(socks5_udp_hdr) + data_len);
		socks5_udp_hdr* hdr = reinterpret_cast<socks5_udp_hdr*>(s5_pkt.data());
		hdr->rsv = 0;
		hdr->frag = 0;
		hdr->atyp = SOCKS5_ATYP_IPV4;
		hdr->dst_ip = flow->orig_dest_ip;
		hdr->dst_port = htons(flow->orig_dest_port);
		memcpy(s5_pkt.data() + sizeof(socks5_udp_hdr), data, data_len);

		sendto(flow->host_fd, s5_pkt.data(), s5_pkt.size(), 0, (struct sockaddr*)&dest_addr,
		    sizeof(dest_addr));
	} else {
		if (rule.redirect_ip && rule.redirect_port) {
			dest_addr.sin_addr.s_addr = rule.redirect_ip;
			dest_addr.sin_port = htons(rule.redirect_port);
		} else {
			uint32_t real_dest_ip = ip->daddr;
			if (real_dest_ip == ctx->host_ip) {
				real_dest_ip = htonl(INADDR_LOOPBACK);
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
		socks5_udp_hdr* hdr = reinterpret_cast<socks5_udp_hdr*>(buf);
		if (hdr->rsv != 0 || hdr->frag != 0) return;

		size_t header_len = 0;
		if (hdr->atyp == SOCKS5_ATYP_IPV4) {
			header_len = 10;
		} else if (hdr->atyp == SOCKS5_ATYP_IPV6) {
			header_len = 22;
		} else if (hdr->atyp == SOCKS5_ATYP_DOMAIN) {
			if (data_len < 5) return;
			header_len = 5 + buf[4] + 2;
		} else {
			return;
		}

		if (data_len < header_len) return;

		data_ptr = buf + header_len;
		data_len -= header_len;
	}

	uint32_t saddr, daddr;
	uint16_t sport, dport;

	daddr = flow->key.saddr;
	dport = flow->key.sport;

	if (flow->is_redirected || flow->use_socks5) {
		saddr = flow->orig_dest_ip;
		sport = htons(flow->orig_dest_port);
	} else {
		saddr = src_addr.sin_addr.s_addr; /* The actual source of the packet */
		sport = src_addr.sin_port;
	}

	udp_send_packet(ctx, saddr, daddr, sport, dport, data_ptr, data_len);
}

void handle_host_udp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule) {
	LOG_D("handle_host_udp_accept listen_fd=%d", listen_fd);

	uint8_t buf[65536];
	struct sockaddr_in client_addr = {};
	socklen_t addrlen = sizeof(client_addr);

	ssize_t recv_len =
	    recvfrom(listen_fd, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &addrlen);
	if (recv_len <= 0) {
		if (recv_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}
		PLOG_E("recvfrom(fd=%d) failed", listen_fd);
		return;
	}

	struct sockaddr_in server_addr = {};
	socklen_t servlen = sizeof(server_addr);
	getsockname(listen_fd, (struct sockaddr*)&server_addr, &servlen);

	FlowKey key = {};
	key.saddr = rule.redirect_ip ? rule.redirect_ip : ctx->guest_ip;
	key.sport = rule.redirect_port ? htons(rule.redirect_port) : server_addr.sin_port;

	uint32_t client_ip = client_addr.sin_addr.s_addr;
	if (client_ip == htonl(INADDR_LOOPBACK)) {
		client_ip = ctx->host_ip; /* Prevent martian drops in guest */
	}

	key.daddr = client_ip;
	key.dport = client_addr.sin_port;

	UdpFlow* flow = nullptr;
	auto it = ctx->udp_flows_by_key.find(key);
	if (it != ctx->udp_flows_by_key.end()) {
		flow = it->second;
		flow->last_active = time(NULL);
	} else {
		if (ctx->udp_flows_by_key.size() >= NSTUN_MAX_FLOWS) {
			LOG_W("Maximum number of UDP flows reached, dropping");
			return;
		}

		/* UDP is connectionless. Create a flow anyway to send packets back */
		flow = new UdpFlow();
		flow->host_fd = listen_fd; /* Use the listener socket to send replies back */
		flow->key = key;
		flow->last_active = time(NULL);
		flow->is_redirected = true;
		flow->use_socks5 = false; /* SOCKS5 inbound not supported yet */
		flow->state = UdpSocks5State::ESTABLISHED;

		/* Inbound flows from listener socket shouldn't be deleted via host_fd mapping when
		 * destroyed */
		flow->host_fd_is_listener = true;

		ctx->udp_flows_by_key[key] = flow;
	}

	/* Construct UDP + IP frame to send to guest */
	uint8_t* data_ptr = buf;
	size_t data_len = recv_len;

	udp_send_packet(ctx, key.daddr, key.saddr, key.dport, key.sport, data_ptr, data_len);
}

} /* namespace nstun */
